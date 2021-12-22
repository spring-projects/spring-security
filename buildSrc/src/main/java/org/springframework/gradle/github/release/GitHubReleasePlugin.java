/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.gradle.github.release;

import groovy.lang.MissingPropertyException;
import org.gradle.api.Action;
import org.gradle.api.Plugin;
import org.gradle.api.Project;

/**
 * @author Steve Riesenberg
 */
public class GitHubReleasePlugin implements Plugin<Project> {
	@Override
	public void apply(Project project) {
		project.getTasks().register("createGitHubRelease", CreateGitHubReleaseTask.class, new Action<CreateGitHubReleaseTask>() {
			@Override
			public void execute(CreateGitHubReleaseTask createGitHubRelease) {
				createGitHubRelease.setGroup("Release");
				createGitHubRelease.setDescription("Create a github release");
				createGitHubRelease.dependsOn("generateChangelog");

				createGitHubRelease.setCreateRelease("true".equals(project.findProperty("createRelease")));
				createGitHubRelease.setVersion((String) project.findProperty("nextVersion"));
				if (project.hasProperty("branch")) {
					createGitHubRelease.setBranch((String) project.findProperty("branch"));
				}
				createGitHubRelease.setGitHubAccessToken((String) project.findProperty("gitHubAccessToken"));
				if (createGitHubRelease.isCreateRelease() && createGitHubRelease.getGitHubAccessToken() == null) {
					throw new MissingPropertyException("Please provide an access token with -PgitHubAccessToken=...");
				}
			}
		});
	}
}
