/*
 * Copyright 2002-2022 the original author or authors.
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

import io.spring.gradle.IncludeRepoTask
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.tasks.GradleBuild
import org.gradle.api.tasks.TaskProvider

/**
 * Adds a set of tasks that make easy to clone a remote repository and perform some task
 *
 * @author Marcus Da Coregio
 */
class IncludeCheckRemotePlugin implements Plugin<Project> {
	@Override
	void apply(Project project) {
		IncludeCheckRemoteExtension extension = project.extensions.create('includeCheckRemote', IncludeCheckRemoteExtension)
		TaskProvider<IncludeRepoTask> includeRepoTask = project.tasks.register('includeRepo', IncludeRepoTask) { IncludeRepoTask it ->
			it.repository = extension.repository
			it.ref = extension.ref
		}
		project.tasks.register('checkRemote', GradleBuild) {
			it.dependsOn 'includeRepo'
			it.dir = includeRepoTask.get().outputDirectory
			it.tasks = extension.getTasks()
			extension.getInitScripts().forEach {script ->
				it.startParameter.addInitScript(new File(script))
			}
			extension.getProjectProperties().entrySet().forEach { entry ->
				it.startParameter.projectProperties.put(entry.getKey(), entry.getValue())
			}
		}
	}

	abstract static class IncludeCheckRemoteExtension {

		/**
		 * Git repository to clone
		 */
		String repository;

		/**
		 * Git ref to checkout
		 */
		String ref

		/**
		 * Task to run in the repository
		 */
		List<String> tasks = ['check']

		/**
		 * Init scripts for the build
		 */
		List<String> initScripts = []

		/**
		 * Map of properties for the build
		 */
		Map<String, String> projectProperties = [:]

	}

}
