/*
 * Copyright 2019-2022 the original author or authors.
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

package org.springframework.security.convention.versions;

import org.gradle.api.Action;
import org.gradle.api.Plugin;
import org.gradle.api.Project;

public class UpdateProjectVersionPlugin implements Plugin<Project> {
	@Override
	public void apply(Project project) {
		project.getTasks().register("updateProjectVersion", UpdateProjectVersionTask.class, new Action<UpdateProjectVersionTask>() {
			@Override
			public void execute(UpdateProjectVersionTask updateProjectVersionTask) {
				updateProjectVersionTask.setGroup("Release");
				updateProjectVersionTask.setDescription("Updates the project version to the next release in gradle.properties");
				updateProjectVersionTask.dependsOn("gitHubNextReleaseMilestone");
				updateProjectVersionTask.getNextVersionFile().fileProvider(project.provider(() -> project.file("next-release.yml")));
			}
		});
		project.getTasks().register("updateToSnapshotVersion", UpdateToSnapshotVersionTask.class, new Action<UpdateToSnapshotVersionTask>() {
			@Override
			public void execute(UpdateToSnapshotVersionTask updateToSnapshotVersionTask) {
				updateToSnapshotVersionTask.setGroup("Release");
				updateToSnapshotVersionTask.setDescription(
						"Updates the project version to the next snapshot in gradle.properties");
			}
		});
	}
}
