/*
 * Copyright 2002-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package io.spring.gradle.convention

import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.publish.maven.plugins.MavenPublishPlugin

class ArtifactoryPlugin implements Plugin<Project> {

	private static final String ARTIFACTORY_URL_NAME = "ARTIFACTORY_URL"

	private static final String ARTIFACTORY_SNAPSHOT_REPOSITORY = "ARTIFACTORY_SNAPSHOT_REPOSITORY"

	private static final String ARTIFACTORY_MILESTONE_REPOSITORY = "ARTIFACTORY_MILESTONE_REPOSITORY"

	private static final String ARTIFACTORY_RELEASE_REPOSITORY = "ARTIFACTORY_RELEASE_REPOSITORY"

	private static final String DEFAULT_ARTIFACTORY_URL = "https://repo.spring.io"

	private static final String DEFAULT_ARTIFACTORY_SNAPSHOT_REPOSITORY = "libs-snapshot-local"

	private static final String DEFAULT_ARTIFACTORY_MILESTONE_REPOSITORY = "libs-milestone-local"

	private static final String DEFAULT_ARTIFACTORY_RELEASE_REPOSITORY = "libs-release-local"

	@Override
	void apply(Project project) {
		project.plugins.apply('com.jfrog.artifactory')
		String name = Utils.getProjectName(project);
		boolean isSnapshot = Utils.isSnapshot(project);
		boolean isMilestone = Utils.isMilestone(project);
		Map<String, String> env = System.getenv()
		String artifactoryUrl = env.getOrDefault(ARTIFACTORY_URL_NAME, DEFAULT_ARTIFACTORY_URL)
		String snapshotRepository = env.getOrDefault(ARTIFACTORY_SNAPSHOT_REPOSITORY, DEFAULT_ARTIFACTORY_SNAPSHOT_REPOSITORY)
		String milestoneRepository = env.getOrDefault(ARTIFACTORY_MILESTONE_REPOSITORY, DEFAULT_ARTIFACTORY_MILESTONE_REPOSITORY)
		String releaseRepository = env.getOrDefault(ARTIFACTORY_RELEASE_REPOSITORY, DEFAULT_ARTIFACTORY_RELEASE_REPOSITORY)
		project.artifactory {
			contextUrl = artifactoryUrl
			publish {
				repository {
					repoKey = isSnapshot ? snapshotRepository : isMilestone ? milestoneRepository : releaseRepository
					if(project.hasProperty('artifactoryUsername')) {
						username = artifactoryUsername
						password = artifactoryPassword
					}
				}
			}
		}
		project.plugins.withType(MavenPublishPlugin) {
			project.artifactory {
				publish {
					defaults {
						publications('mavenJava')
					}
				}
			}
		}
	}
}
