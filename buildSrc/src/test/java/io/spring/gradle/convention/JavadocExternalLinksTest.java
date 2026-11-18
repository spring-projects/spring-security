/*
 * Copyright 2004-present the original author or authors.
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

package io.spring.gradle.convention;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class JavadocExternalLinksTest {

	@Test
	void externalLinksIncludeSpringFrameworkSpringLdapAndJdk() {
		assertThat(JavadocExternalLinks.externalLinks("7.1.0-M2", "4.2.0-M1")).containsExactly(
				"https://docs.spring.io/spring-framework/docs/7.1.0-M2/javadoc-api/",
				"https://docs.spring.io/spring-ldap/docs/current/api/",
				"https://docs.oracle.com/en/java/javase/17/docs/api/");
	}

	@Test
	void springLdapJavadocUrlUsesReleaseVersionWhenAvailable() {
		assertThat(JavadocExternalLinks.springLdapJavadocUrl("4.0.0"))
			.isEqualTo("https://docs.spring.io/spring-ldap/docs/4.0.0/api/");
	}

}
