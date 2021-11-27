/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.gradle.propdeps


import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.plugins.ide.idea.IdeaPlugin

/**
 * Plugin to allow optional and provided dependency configurations to work with the
 * standard gradle 'idea' plugin
 *
 * @author Phillip Webb
 * @author Brian Clozel
 * @link https://youtrack.jetbrains.com/issue/IDEA-107046
 * @link https://youtrack.jetbrains.com/issue/IDEA-117668
 */
class PropDepsIdeaPlugin implements Plugin<Project> {

	public void apply(Project project) {
		project.plugins.apply(PropDepsPlugin)
		project.plugins.apply(IdeaPlugin)
		project.idea.module {
			// IDEA internally deals with 4 scopes : COMPILE, TEST, PROVIDED, RUNTIME
			// but only PROVIDED seems to be picked up
			scopes.PROVIDED.plus += [project.configurations.provided]
			scopes.PROVIDED.plus += [project.configurations.optional]
		}
	}

}
