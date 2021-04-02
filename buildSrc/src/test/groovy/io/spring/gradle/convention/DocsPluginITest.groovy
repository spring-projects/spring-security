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

import io.spring.gradle.testkit.junit.rules.TestKit
import org.gradle.testkit.runner.BuildResult
import org.junit.Rule
import spock.lang.Specification

import java.util.zip.ZipFile

import static org.gradle.testkit.runner.TaskOutcome.FAILED
import static org.gradle.testkit.runner.TaskOutcome.SUCCESS

class DocsPluginITest extends Specification {
	@Rule final TestKit testKit = new TestKit()

	def "build triggers docs"() {
		when:
		BuildResult result = testKit.withProjectResource("samples/docs/simple/")
			.withArguments('build')
			.build();
		then:
		result.task(":build").outcome == SUCCESS
		and:
		result.task(":docs").outcome == SUCCESS
		and:
		result.task(":docsZip").outcome == SUCCESS
		and:
		def zip = new File(testKit.getRootDir(), 'build/distributions/simple-1.0.0.BUILD-SNAPSHOT-docs.zip')
		def names = new ZipFile(zip).entries()*.name
		names.contains("docs/reference/html5/index.html")
		names.contains("docs/reference/pdf/simple-reference.pdf")
	}

	def "asciidoc copies images"() {
		when:
		BuildResult result = testKit.withProjectResource("samples/docs/simple/")
				.withArguments('asciidoctor')
				.build();
		then:
		result.task(":asciidoctor").outcome == SUCCESS
		new File(testKit.getRootDir(), "build/docs/asciidoc/images").exists()
	}

	def "asciidoc docinfo from resources used"() {
		when:
		BuildResult result = testKit.withProjectResource("samples/docs/simple/")
				.withArguments('asciidoctor')
				.build();
		then:
		result.task(":asciidoctor").outcome == SUCCESS
		new File(testKit.getRootDir(), "build/docs/asciidoc/index.html").getText().contains("""<script type="text/javascript" src="js/tocbot/tocbot.min.js"></script>""")
	}

	def "missing attribute fails"() {
		when:
		BuildResult result = testKit.withProjectResource("samples/docs/missing-attribute/")
				.withArguments(':asciidoctor')
				.buildAndFail();
		then:
		result.task(":asciidoctor").outcome == FAILED
	}

	def "missing include"() {
		when:
		BuildResult result = testKit.withProjectResource("samples/docs/missing-include/")
				.withArguments(':asciidoctor')
				.buildAndFail();
		then:
		result.task(":asciidoctor").outcome == FAILED
	}

	def "missing cross reference"() {
		when:
		BuildResult result = testKit.withProjectResource("samples/docs/missing-cross-reference/")
				.withArguments(':asciidoctor')
				.buildAndFail();
		then:
		result.task(":asciidoctor").outcome == FAILED
	}
}
