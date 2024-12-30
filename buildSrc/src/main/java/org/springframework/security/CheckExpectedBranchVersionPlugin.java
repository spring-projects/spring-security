/*
 * Copyright 2002-2024 the original author or authors.
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
import org.gradle.api.plugins.JavaBasePlugin;
import org.gradle.api.provider.Property;
import org.gradle.api.tasks.CacheableTask;
import org.gradle.api.tasks.Input;
import org.gradle.api.tasks.OutputFile;
import org.gradle.api.tasks.TaskAction;
import org.gradle.api.tasks.TaskExecutionException;
import org.gradle.api.tasks.TaskProvider;
import org.gradle.api.tasks.VerificationException;

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
			task.onlyIf("skipCheckExpectedBranchVersion property is false or not present", CheckExpectedBranchVersionPlugin::skipPropertyFalseOrNotPresent);
			task.getVersion().convention(project.provider(() -> project.getVersion().toString()));
			task.getBranchName().convention(project.getProviders().exec(execSpec -> execSpec.setCommandLine("git", "symbolic-ref", "--short", "HEAD")).getStandardOutput().getAsText());
			task.getOutputFile().convention(project.getLayout().getBuildDirectory().file("check-expected-branch-version"));
		});
		project.getTasks().named(JavaBasePlugin.CHECK_TASK_NAME, checkTask -> checkTask.dependsOn(checkExpectedBranchVersionTask));
	}

	private static boolean skipPropertyFalseOrNotPresent(Task task) {
		return task.getProject()
				.getProviders()
				.gradleProperty("skipCheckExpectedBranchVersion")
				.orElse("false")
				.map("false"::equalsIgnoreCase)
				.get();
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
			if (!branchVersion.matches("^[0-9]+\\.[0-9]+\\.x$")) {
				String msg = String.format("Branch version [%s] does not match *.x, ignoring", branchVersion);
				getLogger().warn(msg);
				writeExpectedVersionOutput(msg);
				return;
			}
			if (!versionsMatch(version, branchVersion)) {
				String msg = String.format("Project version [%s] does not match branch version [%s]. " +
						"Please verify that the branch contains the right version.", version, branchVersion);
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
