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

import org.junit.Test;

import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class BasicAuthenticationTests extends AbstractWebServerIntegrationTests {

	@Test
	public void httpBasicWhenAuthenticationRequiredAndNotAuthenticatedThen401() throws Exception {
		MockMvc mockMvc = createMockMvc("classpath:/spring/http-security-basic.xml",
				"classpath:/spring/in-memory-provider.xml", "classpath:/spring/testapp-servlet.xml");
		mockMvc.perform(get("/secure/index")).andExpect(status().isUnauthorized());
	}

	@Test
	public void httpBasicWhenProvidedThen200() throws Exception {
		MockMvc mockMvc = createMockMvc("classpath:/spring/http-security-basic.xml",
				"classpath:/spring/in-memory-provider.xml", "classpath:/spring/testapp-servlet.xml");
		MockHttpServletRequestBuilder request = get("/secure/index").with(httpBasic("johnc", "johncspassword"));
		mockMvc.perform(request).andExpect(status().isOk());
	}

}
