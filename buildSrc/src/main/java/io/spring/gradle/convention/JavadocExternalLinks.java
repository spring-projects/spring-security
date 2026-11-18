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

import java.util.List;

/**
 * External Javadoc URLs for aggregated API documentation.
 */
public final class JavadocExternalLinks {

	/**
	 * Matches {@code options.release} in {@code java-toolchain.gradle}.
	 */
	private static final int JDK_API_VERSION = 17;

	private JavadocExternalLinks() {
	}

	public static int jdkApiVersion() {
		return JDK_API_VERSION;
	}

	public static String springFrameworkJavadocUrl(String springFrameworkVersion) {
		return "https://docs.spring.io/spring-framework/docs/" + springFrameworkVersion + "/javadoc-api/";
	}

	public static String springLdapJavadocUrl(String springLdapVersion) {
		String documentationVersion = springLdapVersion;
		if (springLdapVersion.contains("-")) {
			documentationVersion = "current";
		}
		return "https://docs.spring.io/spring-ldap/docs/" + documentationVersion + "/api/";
	}

	public static String jdkJavadocUrl(int jdkVersion) {
		return "https://docs.oracle.com/en/java/javase/" + jdkVersion + "/docs/api/";
	}

	public static List<String> externalLinks(String springFrameworkVersion, String springLdapVersion) {
		return List.of(springFrameworkJavadocUrl(springFrameworkVersion), springLdapJavadocUrl(springLdapVersion),
				jdkJavadocUrl(jdkApiVersion()));
	}

}
