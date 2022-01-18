/*
 * Copyright 2012-2022 the original author or authors.
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

package org.springframework.gradle.classpath;

import org.gradle.api.Plugin;
import org.gradle.api.Project;
import org.gradle.api.artifacts.Configuration;
import org.gradle.api.artifacts.ConfigurationContainer;
import org.gradle.api.plugins.JavaBasePlugin;
import org.gradle.api.tasks.SourceSetContainer;
import org.gradle.api.tasks.TaskProvider;
import org.gradle.language.base.plugins.LifecycleBasePlugin;
import org.springframework.util.StringUtils;

/**
 * @author Andy Wilkinson
 * @author Rob Winch
 */
public class CheckClasspathForProhibitedDependenciesPlugin implements Plugin<Project> {

	@Override
	public void apply(Project project) {
		project.getPlugins().apply(CheckProhibitedDependenciesLifecyclePlugin.class);
		project.getPlugins().withType(JavaBasePlugin.class, javaBasePlugin -> {
			configureProhibitedDependencyChecks(project);
		});
	}

	private void configureProhibitedDependencyChecks(Project project) {
		SourceSetContainer sourceSets = project.getExtensions().getByType(SourceSetContainer.class);
		sourceSets.all((sourceSet) -> createProhibitedDependenciesChecks(project,
				sourceSet.getCompileClasspathConfigurationName(), sourceSet.getRuntimeClasspathConfigurationName()));
	}

	private void createProhibitedDependenciesChecks(Project project, String... configurationNames) {
		ConfigurationContainer configurations = project.getConfigurations();
		for (String configurationName : configurationNames) {
			Configuration configuration = configurations.getByName(configurationName);
			createProhibitedDependenciesCheck(configuration, project);
		}
	}

	private void createProhibitedDependenciesCheck(Configuration classpath, Project project) {
		String taskName = "check" + StringUtils.capitalize(classpath.getName() + "ForProhibitedDependencies");
		TaskProvider<CheckClasspathForProhibitedDependencies> checkClasspathTask = project.getTasks().register(taskName,
				CheckClasspathForProhibitedDependencies.class, checkClasspath -> {
					checkClasspath.setGroup(LifecycleBasePlugin.CHECK_TASK_NAME);
					checkClasspath.setDescription("Checks " + classpath.getName() + " for prohibited dependencies");
					checkClasspath.setClasspath(classpath);
				});
		project.getTasks().named(CheckProhibitedDependenciesLifecyclePlugin.CHECK_PROHIBITED_DEPENDENCIES_TASK_NAME, checkProhibitedTask -> checkProhibitedTask.dependsOn(checkClasspathTask));
	}
}
