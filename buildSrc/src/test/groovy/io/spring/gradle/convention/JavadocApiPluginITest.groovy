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
package io.spring.gradle.convention

import org.gradle.testkit.runner.BuildResult
import org.gradle.testkit.runner.GradleRunner
import org.junit.Rule
import org.junit.rules.TemporaryFolder
import spock.lang.Specification

import static org.gradle.testkit.runner.TaskOutcome.*;

import io.spring.gradle.testkit.junit.rules.TestKit
import org.apache.commons.io.FileUtils

class JavadocApiPluginITest extends Specification {
	@Rule final TestKit testKit = new TestKit()

	def "multimodule api"() {
		when:
		BuildResult result = testKit.withProjectResource("samples/javadocapi/multimodule/")
			.withArguments('api')
			.build();
		then:
		result.task(":api").outcome == SUCCESS
		and:
		File allClasses = new File(testKit.getRootDir(), 'build/api/allclasses-noframe.html');
		File index = new File(testKit.getRootDir(), 'build/api/allclasses.html');
        new File(testKit.getRootDir(), "build/api/").listFiles().each { println it }
		File listing = allClasses.exists() ? allClasses : index
		listing.text.contains('sample/Api.html')
        listing.text.contains('sample/Impl.html')
		!listing.text.contains('sample/Sample.html')
	}
}
