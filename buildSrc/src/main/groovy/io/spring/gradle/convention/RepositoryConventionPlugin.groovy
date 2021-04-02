/*
 * Copyright 2016-2018 the original author or authors.
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

package io.spring.gradle.convention;

import org.gradle.api.Plugin
import org.gradle.api.Project

class RepositoryConventionPlugin implements Plugin<Project> {

	@Override
	void apply(Project project) {
		String[] forceMavenRepositories = ((String) project.findProperty("forceMavenRepositories"))?.split(',')
		boolean isImplicitSnapshotRepository = forceMavenRepositories == null && Utils.isSnapshot(project)
		boolean isImplicitMilestoneRepository = forceMavenRepositories == null && Utils.isMilestone(project)

		boolean isSnapshot = isImplicitSnapshotRepository || forceMavenRepositories?.contains('snapshot')
		boolean isMilestone = isImplicitMilestoneRepository || forceMavenRepositories?.contains('milestone')

		project.repositories {
			if (forceMavenRepositories?.contains('local')) {
				mavenLocal()
			}
			mavenCentral()
			jcenter() {
				content {
					includeGroup "org.gretty"
				}
			}
			if (isSnapshot) {
				maven {
					name = 'artifactory-snapshot'
					if (project.hasProperty('artifactoryUsername')) {
						credentials {
							username project.artifactoryUsername
							password project.artifactoryPassword
						}
					}
					url = 'https://repo.spring.io/snapshot/'
				}
			}
			if (isSnapshot || isMilestone) {
				maven {
					name = 'artifactory-milestone'
					if (project.hasProperty('artifactoryUsername')) {
						credentials {
							username project.artifactoryUsername
							password project.artifactoryPassword
						}
					}
					url = 'https://repo.spring.io/milestone/'
				}
			}
			maven {
				name = 'artifactory-release'
				if (project.hasProperty('artifactoryUsername')) {
					credentials {
						username project.artifactoryUsername
						password project.artifactoryPassword
					}
				}
				url = 'https://repo.spring.io/release/'
			}
		}
	}

}
