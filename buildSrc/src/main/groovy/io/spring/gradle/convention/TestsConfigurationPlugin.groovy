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
package io.spring.gradle.convention;

import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.plugins.JavaPlugin
import org.gradle.jvm.tasks.Jar

/**
 * Adds the ability to depends on the test jar within other projects using:
 *
 * <code>
 * testCompile project(path: ':foo', configuration: 'tests')
 * </code>
 *
 * @author Rob Winch
 */
public class TestsConfigurationPlugin implements Plugin<Project> {
	@Override
	public void apply(Project project) {
		project.plugins.withType(JavaPlugin) {
			applyJavaProject(project)
		}
	}

	private void applyJavaProject(Project project) {
		project.configurations {
			tests.extendsFrom testRuntime, testRuntimeClasspath
		}

		project.tasks.create('testJar', Jar) {
			classifier = 'test'
			from project.sourceSets.test.output
		}

		project.artifacts {
			tests project.testJar
		}
	}
}
