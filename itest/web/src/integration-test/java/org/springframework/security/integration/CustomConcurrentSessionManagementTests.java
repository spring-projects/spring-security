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

import net.sourceforge.jwebunit.junit.WebTester;

import static org.assertj.core.api.Assertions.*;

import org.springframework.security.core.session.SessionRegistry;
import org.testng.annotations.Test;

/**
 * @author Luke Taylor
 */
public class CustomConcurrentSessionManagementTests extends
		AbstractWebServerIntegrationTests {

	protected String getContextConfigLocations() {
		return "/WEB-INF/http-security-custom-concurrency.xml /WEB-INF/in-memory-provider.xml";
	}

	@Test
	public void maxConcurrentLoginsValueIsRespected() throws Exception {
		beginAt("secure/index.html");
		login("jimi", "jimispassword");
		// Login again
		System.out.println("Client: ******* Second login ******* ");
		WebTester tester2 = new WebTester();
		tester2.getTestContext().setBaseUrl(getBaseUrl());
		tester2.beginAt("secure/index.html");
		tester2.setTextField("username", "jimi");
		tester2.setTextField("password", "jimispassword");
		tester2.setIgnoreFailingStatusCodes(true);
		tester2.submit();
		assertThat(tester2.getServerResponse()).contains(
				"Maximum sessions of 1 for this principal exceeded");
	}

	@Test
	public void logoutClearsSessionRegistryAndAllowsSecondLogin() throws Exception {
		beginAt("secure/index.html");
		login("bessie", "bessiespassword");
		SessionRegistry reg = getAppContext().getBean(SessionRegistry.class);

		tester.gotoPage("/logout");

		// Login again
		System.out.println("Client: ******* Second login ******* ");
		WebTester tester2 = new WebTester();
		tester2.getTestContext().setBaseUrl(getBaseUrl());
		tester2.beginAt("secure/index.html");
		tester2.setTextField("username", "bessie");
		tester2.setTextField("password", "bessiespassword");
		tester2.setIgnoreFailingStatusCodes(true);
		tester2.submit();
		assertThat(tester2.getServerResponse()).contains("A secure page");
	}
}
