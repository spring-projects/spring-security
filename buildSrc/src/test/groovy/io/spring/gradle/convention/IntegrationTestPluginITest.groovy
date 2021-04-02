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

import io.spring.gradle.testkit.junit.rules.TestKit
import org.gradle.testkit.runner.BuildResult
import org.junit.Rule
import spock.lang.Specification

import static org.gradle.testkit.runner.TaskOutcome.SUCCESS

class IntegrationTestPluginITest extends Specification {
	@Rule final TestKit testKit = new TestKit()

	def "check with java plugin"() {
		when:
		BuildResult result = testKit.withProjectResource("samples/integrationtest/withjava/")
				.withArguments('check')
				.build();
		then:
		result.task(":check").outcome == SUCCESS
		and:
		new File(testKit.getRootDir(), 'build/test-results/integrationTest/').exists()
		new File(testKit.getRootDir(), 'build/reports/tests/integrationTest/').exists()
	}

	def "check with propdeps"() {
		when:
		BuildResult result = testKit.withProjectResource("samples/integrationtest/withpropdeps/")
				.withArguments('check')
				.build();
		then:
		result.task(":check").outcome == SUCCESS
		and:
		new File(testKit.getRootDir(), 'build/test-results/integrationTest/').exists()
		new File(testKit.getRootDir(), 'build/reports/tests/integrationTest/').exists()
	}

	def "check with groovy plugin"() {
		when:
		BuildResult result = testKit.withProjectResource("samples/integrationtest/withgroovy/")
			.withArguments('check')
			.build();
		then:
		result.task(":check").outcome == SUCCESS
		and:
		new File(testKit.getRootDir(), 'build/test-results/integrationTest/').exists()
		new File(testKit.getRootDir(), 'build/reports/tests/integrationTest/').exists()
	}
}
