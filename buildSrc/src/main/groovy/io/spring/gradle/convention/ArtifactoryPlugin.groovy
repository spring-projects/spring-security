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

	private static final String ARTIFACTORY_PROJECT_KEY = "ARTIFACTORY_PROJECT_KEY"

	private static final String ARTIFACTORY_BUILD_NAME = "ARTIFACTORY_BUILD_NAME"

	private static final String ARTIFACTORY_BUILD_NUMBER = "ARTIFACTORY_BUILD_NUMBER"

	private static final String ARTIFACTORY_BUILD_URL = "ARTIFACTORY_BUILD_URL"

	private static final String ARTIFACTORY_BUILD_AGENT_NAME = "ARTIFACTORY_BUILD_AGENT_NAME"

	private static final String ARTIFACTORY_BUILD_AGENT_VERSION = "ARTIFACTORY_BUILD_AGENT_VERSION"

	private static final String ARTIFACTORY_USER_AGENT_NAME = "ARTIFACTORY_USER_AGENT_NAME"

	private static final String ARTIFACTORY_USER_AGENT_VERSION = "ARTIFACTORY_USER_AGENT_VERSION"

	private static final String ARTIFACTORY_VCS_REVISION = "ARTIFACTORY_VCS_REVISION"

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
		String projectKey = env.get(ARTIFACTORY_PROJECT_KEY)
		String buildName = env.get(ARTIFACTORY_BUILD_NAME)
		String buildNumber = env.get(ARTIFACTORY_BUILD_NUMBER)
		String buildUrl = env.get(ARTIFACTORY_BUILD_URL)
		String buildAgentName = env.get(ARTIFACTORY_BUILD_AGENT_NAME)
		String buildAgentVersion = env.get(ARTIFACTORY_BUILD_AGENT_VERSION)
		String userAgentName = env.get(ARTIFACTORY_USER_AGENT_NAME)
		String userAgentVersion = env.get(ARTIFACTORY_USER_AGENT_VERSION)
		String vcsRevision = env.get(ARTIFACTORY_VCS_REVISION)
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

			def buildInfo = clientConfig.info
			if (projectKey != null) {
				buildInfo.setProject(projectKey)
			}
			if (buildName != null) {
				buildInfo.setBuildName(buildName)
			}
			if (buildNumber != null) {
				buildInfo.setBuildNumber(buildNumber)
			}
			if (buildUrl != null) {
				buildInfo.setBuildUrl(buildUrl)
			}
			if (buildAgentName != null) {
				buildInfo.setBuildAgentName(buildAgentName)
			}
			if (buildAgentVersion != null) {
				buildInfo.setBuildAgentVersion(buildAgentVersion)
			}
			if (userAgentName != null) {
				buildInfo.setAgentName(userAgentName)
			}
			if (userAgentVersion != null) {
				buildInfo.setAgentVersion(userAgentVersion)
			}
			if (vcsRevision != null) {
				buildInfo.setVcsRevision(vcsRevision)
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
