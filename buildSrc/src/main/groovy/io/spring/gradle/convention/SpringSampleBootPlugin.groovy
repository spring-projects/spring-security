/*
 * Copyright 2002-2016 the original author or authors.
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

import org.gradle.api.Project;
import org.gradle.api.plugins.PluginManager;
import org.gradle.api.plugins.WarPlugin
import org.gradle.api.plugins.JavaPlugin;
import org.gradle.api.tasks.testing.Test

/**
 * @author Rob Winch
 */
public class SpringSampleBootPlugin extends SpringSamplePlugin {

	@Override
	public void additionalPlugins(Project project) {
		super.additionalPlugins(project);

		PluginManager pluginManager = project.getPluginManager();

		pluginManager.apply("org.springframework.boot");

		project.repositories {
			maven { url 'https://repo.spring.io/snapshot' }
			maven { url 'https://repo.spring.io/milestone' }
		}
	}
}
