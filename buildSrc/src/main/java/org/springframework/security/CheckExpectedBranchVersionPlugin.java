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

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.gradle.api.DefaultTask;
import org.gradle.api.Plugin;
import org.gradle.api.Project;
import org.gradle.api.plugins.JavaBasePlugin;
import org.gradle.api.tasks.TaskAction;
import org.gradle.api.tasks.TaskProvider;

/**
 * @author Marcus da Coregio
 */
public class CheckExpectedBranchVersionPlugin implements Plugin<Project> {

	@Override
	public void apply(Project project) {
		TaskProvider<CheckExpectedBranchVersionTask> checkExpectedBranchVersionTask = project.getTasks().register("checkExpectedBranchVersion", CheckExpectedBranchVersionTask.class, (task) -> {
			task.setGroup("Build");
			task.setDescription("Check if the project version matches the branch version");
		});
		project.getTasks().named(JavaBasePlugin.CHECK_TASK_NAME, checkTask -> checkTask.dependsOn(checkExpectedBranchVersionTask));
	}

	public static class CheckExpectedBranchVersionTask extends DefaultTask {

		@TaskAction
		public void run() throws IOException {
			Project project = getProject();
			if (project.hasProperty("skipCheckExpectedBranchVersion")) {
				return;
			}
			String version = (String) project.getVersion();
			String branchVersion = getBranchVersion(project);
			if (!branchVersion.matches("^[0-9]+\\.[0-9]+\\.x$")) {
				System.out.println("Branch version '" + branchVersion + "' does not match *.x, ignoring");
				return;
			}
			if (!versionsMatch(version, branchVersion)) {
				throw new IllegalStateException(String.format("Project version [%s] does not match branch version [%s]. " +
						"Please verify that the branch contains the right version.", version, branchVersion));
			}
		}

		private static String getBranchVersion(Project project) throws IOException {
			try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
				project.exec((exec) -> {
					exec.commandLine("git", "symbolic-ref", "--short", "HEAD");
					exec.setErrorOutput(System.err);
					exec.setStandardOutput(baos);
				});
				return baos.toString().trim();
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
