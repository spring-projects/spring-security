/*
 * Copyright 2002-2016 the original author or authors.
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
package org.springframework.security.integration;


import static org.assertj.core.api.Assertions.*;

import org.testng.annotations.Test;

/**
 *
 * @author Luke Taylor
 */
public final class JspTaglibTests extends AbstractWebServerIntegrationTests {

	@Override
	protected String getContextConfigLocations() {
		return "/WEB-INF/http-security.xml /WEB-INF/in-memory-provider.xml";
	}

	@Test
	public void authenticationTagEscapingWorksCorrectly() {
		beginAt("secure/authenticationTagTestPage.jsp");
		login("theescapist<>&.", "theescapistspassword");
		String response = tester.getServerResponse();
		assertThat(response)
				.contains("This is the unescaped authentication name: theescapist<>&.");
		assertThat(response)
				.contains("This is the unescaped principal.username: theescapist<>&.");
		assertThat(response)
				.contains("This is the authentication name: theescapist&lt;&gt;&amp;&#46;");
		assertThat(response)
				.contains("This is the principal.username: theescapist&lt;&gt;&amp;&#46;");
	}

	@Test
	public void authorizationTagEvaluatesExpressionCorrectlyAndWritesValueToVariable() {
		beginAt("secure/authorizationTagTestPage.jsp");
		login("bessie", "bessiespassword");
		String response = tester.getServerResponse();
		assertThat(response)
				.contains("Users can see this and 'allowed' variable is true.");
		assertThat(response).doesNotContain("Role X users (nobody) can see this.");
		assertThat(response).contains("Role X expression evaluates to false");
	}

}
