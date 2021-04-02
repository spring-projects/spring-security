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

import org.gradle.api.Project
import org.gradle.api.Task
import org.gradle.api.plugins.PluginManager
import org.gradle.api.tasks.testing.Test

/**
 * @author Rob Winch
 */
public class SpringSampleWarPlugin extends SpringSamplePlugin {

	@Override
	public void additionalPlugins(Project project) {
		super.additionalPlugins(project);

		PluginManager pluginManager = project.getPluginManager();

		pluginManager.apply("war");
		pluginManager.apply("org.gretty");

		project.gretty {
			servletContainer = 'tomcat85'
			contextPath = '/'
			fileLogEnabled = false
		}

		Task prepareAppServerForIntegrationTests = project.tasks.create('prepareAppServerForIntegrationTests') {
			group = 'Verification'
			description = 'Prepares the app server for integration tests'
			doFirst {
				project.gretty {
					httpPort = getRandomFreePort()
					httpsPort = getRandomPort()
				}
			}
		}
		project.tasks.withType(org.akhikhl.gretty.AppBeforeIntegrationTestTask).all { task ->
			task.dependsOn prepareAppServerForIntegrationTests
		}

		project.tasks.withType(Test).all { task ->
			if("integrationTest".equals(task.name)) {
				applyForIntegrationTest(project, task)
			}
		}
	}

	def applyForIntegrationTest(Project project, Task integrationTest) {
		project.gretty.integrationTestTask = integrationTest.name

		integrationTest.doFirst {
			def gretty = project.gretty
			String host = project.gretty.host ?: 'localhost'
			boolean isHttps = gretty.httpsEnabled
			Integer httpPort = integrationTest.systemProperties['gretty.httpPort']
			Integer httpsPort = integrationTest.systemProperties['gretty.httpsPort']
			int port = isHttps ? httpsPort : httpPort
			String contextPath = project.gretty.contextPath
			String httpBaseUrl = "http://${host}:${httpPort}${contextPath}"
			String httpsBaseUrl = "https://${host}:${httpsPort}${contextPath}"
			String baseUrl = isHttps ? httpsBaseUrl : httpBaseUrl
			integrationTest.systemProperty 'app.port', port
			integrationTest.systemProperty 'app.httpPort', httpPort
			integrationTest.systemProperty 'app.httpsPort', httpsPort
			integrationTest.systemProperty 'app.baseURI', baseUrl
			integrationTest.systemProperty 'app.httpBaseURI', httpBaseUrl
			integrationTest.systemProperty 'app.httpsBaseURI', httpsBaseUrl

			integrationTest.systemProperty 'geb.build.baseUrl', baseUrl
			integrationTest.systemProperty 'geb.build.reportsDir', 'build/geb-reports'
		}
	}

	def getRandomPort() {
		ServerSocket ss = new ServerSocket(0)
		int port = ss.localPort
		ss.close()
		return port
	}
}
