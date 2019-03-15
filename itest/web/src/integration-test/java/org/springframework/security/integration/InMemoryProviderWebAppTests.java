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

import javax.servlet.http.Cookie;

import org.testng.annotations.Test;

/**
 * @author Luke Taylor
 */
public class InMemoryProviderWebAppTests extends AbstractWebServerIntegrationTests {

	protected String getContextConfigLocations() {
		return "/WEB-INF/http-security.xml /WEB-INF/in-memory-provider.xml";
	}

	@Test
	public void loginFailsWithinvalidPassword() {
		beginAt("secure/index.html");
		login("jimi", "wrongPassword");
		assertTextPresent("Your login attempt was not successful");
	}

	@Test
	public void loginSucceedsWithCorrectPassword() {
		beginAt("secure/index.html");
		login("jimi", "jimispassword");
		assertTextPresent("A Secure Page");
		tester.gotoPage("/logout");
	}

	@Test
	public void basicAuthenticationIsSuccessful() throws Exception {
		tester.getTestContext().setAuthorization("johnc", "johncspassword");
		beginAt("secure/index.html");
		beginAt("secure/index.html");
	}

	/*
	 * Checks use of <jsp:include> with parameters in the secured page.
	 */
	@Test
	public void savedRequestWithJspIncludeSeesCorrectParams() {
		beginAt("secure/secure1.jsp?x=0");
		login("jimi", "jimispassword");
		// Included JSP has params ?x=1&y=2
		assertTextPresent("Params: x=1, y=2");
		assertTextPresent("xcount=2");
	}

	// SEC-1255
	@Test
	public void redirectToUrlWithSpecialCharsInFilenameWorksOk() throws Exception {
		beginAt("secure/file%3Fwith%3Fspecial%3Fchars.htm?someArg=1");
		login("jimi", "jimispassword");
		assertTextPresent("I'm file?with?special?chars.htm");
	}

	@Test
	public void persistentLoginIsSuccesful() throws Exception {
		beginAt("secure/index.html");
		tester.checkCheckbox("remember-me");
		login("jimi", "jimispassword");
		Cookie rememberMe = getRememberMeCookie();
		assertThat(rememberMe).isNotNull();
		tester.closeBrowser();

		tester.getTestContext().addCookie(rememberMe);
		beginAt("secure/index.html");
		assertTextPresent("A Secure Page");
	}
}
