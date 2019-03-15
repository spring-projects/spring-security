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

import org.testng.annotations.Test;

public class BasicAuthenticationTests extends AbstractWebServerIntegrationTests {

	@Override
	protected String getContextConfigLocations() {
		return "/WEB-INF/http-security-basic.xml /WEB-INF/in-memory-provider.xml";
	}

	@Test
	public void basicAuthenticationIsSuccessful() throws Exception {
		tester.setIgnoreFailingStatusCodes(true);
		beginAt("secure/index.html");
		// Ignore the 401
		tester.setIgnoreFailingStatusCodes(false);
		tester.assertHeaderEquals("WWW-Authenticate",
				"Basic realm=\"Spring Security Application\"");
		tester.getTestContext().setAuthorization("johnc", "johncspassword");
		beginAt("secure/index.html");
	}

}
