/*
 * Copyright 2016-2019 the original author or authors.
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

import io.spring.nohttp.gradle.NoHttpPlugin
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.plugins.BasePlugin
import org.gradle.api.plugins.PluginManager
import org.springframework.gradle.maven.SpringNexusPublishPlugin

class RootProjectPlugin implements Plugin<Project> {

	@Override
	void apply(Project project) {
		PluginManager pluginManager = project.getPluginManager()
		pluginManager.apply(BasePlugin)
		pluginManager.apply(SchemaPlugin)
		pluginManager.apply(NoHttpPlugin)
        pluginManager.apply(SpringNexusPublishPlugin)
		pluginManager.apply("org.sonarqube")

		project.repositories.mavenCentral()

		String projectName = Utils.getProjectName(project)
		project.sonarqube {
			properties {
				property "sonar.java.coveragePlugin", "jacoco"
				property "sonar.projectName", projectName
				property "sonar.jacoco.reportPath", "${project.buildDir.name}/jacoco.exec"
				property "sonar.links.homepage", "https://spring.io/${projectName}"
				property "sonar.links.ci", "https://jenkins.spring.io/job/${projectName}/"
				property "sonar.links.issue", "https://github.com/spring-projects/${projectName}/issues"
				property "sonar.links.scm", "https://github.com/spring-projects/${projectName}"
				property "sonar.links.scm_dev", "https://github.com/spring-projects/${projectName}.git"
			}
		}

		def finalizeDeployArtifacts = project.task("finalizeDeployArtifacts")
		if (Utils.isRelease(project) && project.hasProperty("ossrhUsername")) {
			finalizeDeployArtifacts.dependsOn project.tasks.closeAndReleaseOssrhtagingRepository
		}
	}

}
