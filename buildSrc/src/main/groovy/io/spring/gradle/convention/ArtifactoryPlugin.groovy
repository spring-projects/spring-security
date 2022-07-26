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

	@Override
	void apply(Project project) {
		project.plugins.apply('com.jfrog.artifactory')
		String name = Utils.getProjectName(project);
		boolean isSnapshot = Utils.isSnapshot(project);
		boolean isMilestone = Utils.isMilestone(project);
		project.artifactory {
			contextUrl = 'https://repo.spring.io'
			publish {
				repository {
					repoKey = isSnapshot ? 'libs-snapshot-local' : isMilestone ? 'libs-milestone-local' : 'libs-release-local'
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
