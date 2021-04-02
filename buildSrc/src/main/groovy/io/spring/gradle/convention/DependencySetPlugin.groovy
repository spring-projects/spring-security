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

/**
 * Adds sets of dependencies to make it easy to add a grouping of dependencies. The
 * dependencies added are:
 *
 * <ul>
 * <li>sockDependencies</li>
 * <li>seleniumDependencies</li>
 * <li>gebDependencies</li>
 * <li>powerMockDependencies</li>
 * <li>slf4jDependencies</li>
 * <li>jstlDependencies</li>
 * <li>apachedsDependencies</li>
 * </ul>
 *
 * @author Rob Winch
 */
public class DependencySetPlugin implements Plugin<Project> {
	@Override
	public void apply(Project project) {

		project.ext.spockDependencies = [
			project.dependencies.create("org.spockframework:spock-spring") {
				exclude group: 'junit', module: 'junit-dep'
			},
			project.dependencies.create("org.spockframework:spock-core") {
				exclude group: 'junit', module: 'junit-dep'
			}
		]

		project.ext.seleniumDependencies = [
				"org.seleniumhq.selenium:htmlunit-driver",
				"org.seleniumhq.selenium:selenium-support"
		]

		project.ext.gebDependencies = project.spockDependencies +
			project.seleniumDependencies + [
			"org.gebish:geb-spock",
			'commons-httpclient:commons-httpclient',
			"org.codehaus.groovy:groovy",
			"org.codehaus.groovy:groovy-all"
		]

		project.ext.powerMockDependencies = [
				"org.powermock:powermock-core",
				"org.powermock:powermock-api-support",
				"org.powermock:powermock-module-junit4-common",
				"org.powermock:powermock-module-junit4",
				project.dependencies.create("org.powermock:powermock-api-mockito") {
					exclude group: 'org.mockito', module: 'mockito-all'
				},
				"org.powermock:powermock-reflect"
		]

		project.ext.powerMock2Dependencies = [
				"org.powermock:powermock-core",
				"org.powermock:powermock-api-support",
				"org.powermock:powermock-module-junit4-common",
				"org.powermock:powermock-module-junit4",
				project.dependencies.create("org.powermock:powermock-api-mockito2") {
					exclude group: 'org.mockito', module: 'mockito-all'
				},
				"org.powermock:powermock-reflect"
		]

		project.ext.slf4jDependencies = [
			"org.slf4j:slf4j-api",
			"org.slf4j:jcl-over-slf4j",
			"org.slf4j:log4j-over-slf4j",
			"ch.qos.logback:logback-classic"
		]

		project.ext.springCoreDependency = [
			project.dependencies.create("org.springframework:spring-core") {
				exclude(group: 'commons-logging', module: 'commons-logging')
			}
		]

		project.ext.testDependencies = [
			"junit:junit",
			"org.mockito:mockito-core",
			"org.springframework:spring-test",
			"org.assertj:assertj-core"
		]

		project.ext.jstlDependencies = [
				"javax.servlet.jsp.jstl:javax.servlet.jsp.jstl-api",
				"org.apache.taglibs:taglibs-standard-jstlel"
		]

		project.ext.apachedsDependencies = [
				"org.apache.directory.server:apacheds-core",
				"org.apache.directory.server:apacheds-core-entry",
				"org.apache.directory.server:apacheds-protocol-shared",
				"org.apache.directory.server:apacheds-protocol-ldap",
				"org.apache.directory.server:apacheds-server-jndi",
				'org.apache.directory.shared:shared-ldap'
		]

		project.plugins.withType(JavaPlugin) {
			project.dependencies {
				testCompile project.testDependencies
			}
		}
	}
}
