/*
 * Copyright 2004-present the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security;

import org.gradle.api.DefaultTask;
import org.gradle.api.Plugin;
import org.gradle.api.Project;
import org.gradle.api.Task;
import org.gradle.api.file.RegularFileProperty;
import org.gradle.api.logging.Logger;
import org.gradle.api.plugins.JavaBasePlugin;
import org.gradle.api.provider.Property;
import org.gradle.api.provider.Provider;
import org.gradle.api.provider.ProviderFactory;
import org.gradle.api.specs.Spec;
import org.gradle.api.tasks.CacheableTask;
import org.gradle.api.tasks.Input;
import org.gradle.api.tasks.OutputFile;
import org.gradle.api.tasks.TaskAction;
import org.gradle.api.tasks.TaskExecutionException;
import org.gradle.api.tasks.TaskProvider;
import org.gradle.api.tasks.VerificationException;
import org.gradle.process.ExecOutput;

import java.io.IOException;
import java.nio.file.Files;

/**
 * @author Marcus da Coregio
 */
public class CheckExpectedBranchVersionPlugin implements Plugin<Project> {

	@Override
	public void apply(Project project) {
		TaskProvider<CheckExpectedBranchVersionTask> checkExpectedBranchVersionTask = project.getTasks().register("checkExpectedBranchVersion", CheckExpectedBranchVersionTask.class, (task) -> {
			task.setGroup("Build");
			task.setDescription("Check if the project version matches the branch version");
			task.onlyIf("Property 'skipCheckExpectedBranchVersion' is false or not present", skipPropertyFalseOrNotPresent(project.getProviders()));
			task.onlyIf("Branch name matches expected version pattern *.x", CheckExpectedBranchVersionPlugin::isVersionBranch);
			task.getVersion().convention(project.provider(() -> project.getVersion().toString()));
			task.getBranchName().convention(getBranchName(project.getProviders(), project.getLogger()));
			task.getOutputFile().convention(project.getLayout().getBuildDirectory().file("check-expected-branch-version"));
		});
		project.getTasks().named(JavaBasePlugin.CHECK_TASK_NAME, checkTask -> checkTask.dependsOn(checkExpectedBranchVersionTask));
	}

	private static Spec<Task> skipPropertyFalseOrNotPresent(ProviderFactory providers) {
		Provider<Boolean> skipPropertyFalseOrNotPresent = providers
				.gradleProperty("skipCheckExpectedBranchVersion")
				.orElse("false")
				.map("false"::equalsIgnoreCase);
		return (task) -> skipPropertyFalseOrNotPresent.get();
	}

	private static boolean isVersionBranch(Task task) {
		return isVersionBranch((CheckExpectedBranchVersionTask) task);
	}

	private static boolean isVersionBranch(CheckExpectedBranchVersionTask task) {
		String branchName = task.getBranchName().getOrNull();
		if (branchName == null) {
			return false;
		}
		return branchName.matches("^[0-9]+\\.[0-9]+\\.x$");
	}

	private static Provider<String> getBranchName(ProviderFactory providers, Logger logger) {
		ExecOutput execOutput = providers.exec((execSpec) -> {
			execSpec.setCommandLine("git", "symbolic-ref", "--short", "HEAD");
			execSpec.setIgnoreExitValue(true);
		});

		return providers.provider(() -> {
			int exitValue = execOutput.getResult().get().getExitValue();
			if (exitValue != 0) {
				logger.warn("Unable to determine branch name. Received exit code '{}' from `git`.", exitValue);
				logger.warn(execOutput.getStandardError().getAsText().getOrNull());
				return null;
			}

			String branchName = execOutput.getStandardOutput().getAsText().get().trim();
			logger.info("Git branch name is '{}'.", branchName);
			return branchName;
		});
	}

	@CacheableTask
	public static abstract class CheckExpectedBranchVersionTask extends DefaultTask {

		@Input
		abstract Property<String> getVersion();

		@Input
		abstract Property<String> getBranchName();

		@OutputFile
		abstract RegularFileProperty getOutputFile();

		@TaskAction
		public void run() {
			String version = getVersion().get();
			String branchVersion = getBranchName().map(String::trim).get();
			if (!versionsMatch(version, branchVersion)) {
				String msg = String.format("Project version [%s] does not match branch version [%s]. " +
						"Please verify that the branch contains the right version. " +
						"To bypass this check, run the build with -PskipCheckExpectedBranchVersion.", version, branchVersion);
				writeExpectedVersionOutput(msg);
				throw new VerificationException(msg);
			}

			writeExpectedVersionOutput(version);
		}

		private void writeExpectedVersionOutput(String fileContent) {
			try {
				Files.writeString(getOutputFile().get().getAsFile().toPath(), fileContent);
			} catch (IOException e) {
				throw new TaskExecutionException(this, e);
			}
		}

		private boolean versionsMatch(String projectVersion, String branchVersion) {
			String[] projectVersionParts = projectVersion.split("\\.");
			String[] branchVersionParts = branchVersion.split("\\.");
			if (projectVersionParts.length < 2 || branchVersionParts.length < 2) {
				return false;
			}
			return projectVersionParts[0].equals(branchVersionParts[0]) && projectVersionParts[1].equals(branchVersionParts[1]);
		}

	}

}
