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

import java.util.Collections;
import java.util.List;

import org.junit.Test;

import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.session.SessionDestroyedEvent;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.CoreMatchers.containsString;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * @author Luke Taylor
 */
public class ConcurrentSessionManagementTests extends AbstractWebServerIntegrationTests {

	@Test
	public void maxConcurrentLoginsValueIsRespected() throws Exception {
		final MockHttpSession session1 = new MockHttpSession();
		final MockHttpSession session2 = new MockHttpSession();

		MockMvc mockMvc = createMockMvc("classpath:/spring/http-security-concurrency.xml",
				"classpath:/spring/in-memory-provider.xml", "classpath:/spring/testapp-servlet.xml");

		mockMvc.perform(get("/secure/index").session(session1)).andExpect(status().is3xxRedirection());

		MockHttpServletRequestBuilder login1 = login().session(session1);
		mockMvc.perform(login1).andExpect(authenticated().withUsername("jimi"));

		MockHttpServletRequestBuilder login2 = login().session(session2);
		mockMvc.perform(login2).andExpect(redirectedUrl("/login.jsp?login_error=true"));
		Exception exception = (Exception) session2.getAttribute("SPRING_SECURITY_LAST_EXCEPTION");
		assertThat(exception).isNotNull();
		assertThat(exception.getMessage()).contains("Maximum sessions of 1 for this principal exceeded");

		// Now logout to kill first session
		mockMvc.perform(post("/logout").with(csrf())).andExpect(status().is3xxRedirection())
				.andDo((result) -> this.context.publishEvent(new SessionDestroyedEvent(session1) {
					@Override
					public List<SecurityContext> getSecurityContexts() {
						return Collections.emptyList();
					}

					@Override
					public String getId() {
						return session1.getId();
					}
				}));

		// Try second session again
		login2 = login().session(session2);
		mockMvc.perform(login2).andExpect(authenticated().withUsername("jimi"));

		mockMvc.perform(get("/secure/index").session(session2))
				.andExpect(content().string(containsString("A Secure Page")));
	}

	private MockHttpServletRequestBuilder login() {
		return post("/login").param("username", "jimi").param("password", "jimispassword").with(csrf());
	}

}
