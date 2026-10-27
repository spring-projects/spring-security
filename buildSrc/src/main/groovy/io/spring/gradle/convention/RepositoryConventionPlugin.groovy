/*
 * Copyright 2004-present the original author or authors.
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

package io.spring.gradle.convention;

import org.gradle.api.Plugin
import org.gradle.api.Project
import org.springframework.gradle.repository.SpringRepositoryPlugin

/**
 * Applies {@link SpringRepositoryPlugin} and then adds the repository content filters
 * that Spring Security needs on top of it.
 */
class RepositoryConventionPlugin implements Plugin<Project> {

	@Override
	void apply(Project project) {
		project.pluginManager.apply(SpringRepositoryPlugin)
		// SpringRepositoryPlugin adds its repositories in afterEvaluate; this runs after it
		project.afterEvaluate {
			project.repositories.getByName('spring-oss-release').content {
				excludeGroup('net.minidev')
			}
			project.repositories.maven {
				name = 'shibboleth'
				url = 'https://build.shibboleth.net/nexus/content/repositories/releases/'
				content {
					includeGroupByRegex('org\\.opensaml.*')
					includeGroupByRegex('net\\.shibboleth.*')
				}
			}
		}
	}

}
