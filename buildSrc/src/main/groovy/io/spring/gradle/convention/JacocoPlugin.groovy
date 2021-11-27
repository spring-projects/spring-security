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

package io.spring.gradle.convention

import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.plugins.JavaPlugin

/**
 * Adds a version of jacoco to use and makes check depend on jacocoTestReport.
 *
 * @author Rob Winch
 */
class JacocoPlugin implements Plugin<Project> {

	@Override
	void apply(Project project) {
		project.plugins.withType(JavaPlugin) {
			project.getPluginManager().apply("jacoco")
			project.tasks.check.dependsOn project.tasks.jacocoTestReport

			project.jacoco {
				toolVersion = '0.8.7'
			}
		}
	}
}
