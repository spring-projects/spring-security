/*
 * Copyright 2019-2020 the original author or authors.
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

package org.springframework.gradle.sagan;

import io.spring.gradle.convention.Utils;
import org.gradle.api.*;

public class SaganPlugin implements Plugin<Project> {
	@Override
	public void apply(Project project) {
		project.getTasks().register("saganCreateRelease", SaganCreateReleaseTask.class, new Action<SaganCreateReleaseTask>() {
			@Override
			public void execute(SaganCreateReleaseTask saganCreateVersion) {
				saganCreateVersion.setGroup("Release");
				saganCreateVersion.setDescription("Creates a new version for the specified project on spring.io");
				saganCreateVersion.setVersion((String) project.findProperty("nextVersion"));
				saganCreateVersion.setProjectName(Utils.getProjectName(project));
				saganCreateVersion.setGitHubAccessToken((String) project.findProperty("gitHubAccessToken"));
			}
		});
		project.getTasks().register("saganDeleteRelease", SaganDeleteReleaseTask.class, new Action<SaganDeleteReleaseTask>() {
			@Override
			public void execute(SaganDeleteReleaseTask saganDeleteVersion) {
				saganDeleteVersion.setGroup("Release");
				saganDeleteVersion.setDescription("Delete a version for the specified project on spring.io");
				saganDeleteVersion.setVersion((String) project.findProperty("previousVersion"));
				saganDeleteVersion.setProjectName(Utils.getProjectName(project));
				saganDeleteVersion.setGitHubAccessToken((String) project.findProperty("gitHubAccessToken"));
			}
		});
	}

}
