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

import io.spring.gradle.testkit.junit.rules.TestKit
import org.gradle.testkit.runner.BuildResult
import org.junit.Rule
import spock.lang.Specification

import static org.gradle.testkit.runner.TaskOutcome.SUCCESS

class SpringMavenPluginITest extends Specification {

	@Rule final TestKit testKit = new TestKit()

	def "install"() {
		when:
		BuildResult result = testKit.withProjectResource("samples/maven/install")
			.withArguments('install')
			.build();
		then: 'pom contains optional'
		result.output.contains("SUCCESS")
		File pom = new File(testKit.getRootDir(), 'build/poms/pom-default.xml')
		pom.exists()
		String pomText = pom.getText()
		pomText.replaceAll('\\s','').contains("""<dependency>
			<groupId>aopalliance</groupId>
			<artifactId>aopalliance</artifactId>
			<version>1.0</version>
			<scope>compile</scope>
			<optional>true</optional>
		</dependency>""".replaceAll('\\s',''))
	}

	def "signArchives when in memory"() {
		when:
		BuildResult result = testKit.withProjectResource("samples/maven/signing")
				.withArguments('signArchives')
				.withEnvironment(["ORG_GRADLE_PROJECT_signingKey" : signingKey,
								  "ORG_GRADLE_PROJECT_signingPassword" : "password"])
				.forwardOutput()
				.build();
		then:
		result.output.contains("SUCCESS")
		File jar = new File(testKit.getRootDir(), 'build/libs/signing-1.0.0.RELEASE.jar')
		jar.exists()
		File signature = new File("${jar.absolutePath}.asc")
		signature.exists()
	}

	def "upload"() {
		when:
		BuildResult result = testKit.withProjectResource("samples/maven/upload")
				.withArguments('uploadArchives')
				.forwardOutput()
				.build();
		then: 'pom contains optional'
		result.output.contains("SUCCESS")
		File pom = new File(testKit.getRootDir(), 'build/poms/pom-default.xml')
		pom.exists()
		String pomText = pom.getText()
		pomText.replaceAll('\\s','').contains("""<dependency>
			<groupId>aopalliance</groupId>
			<artifactId>aopalliance</artifactId>
			<version>1.0</version>
			<scope>compile</scope>
			<optional>true</optional>
			</dependency>""".replaceAll('\\s',''))
	}

	def getSigningKey() {
		getClass().getResource("/test-private.pgp").text
	}
}
