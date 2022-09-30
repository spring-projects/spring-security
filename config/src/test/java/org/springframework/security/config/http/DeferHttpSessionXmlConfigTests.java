/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.config.http;

import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.web.FilterChainProxy;

import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

/**
 * @author Rob Winch
 */
@ExtendWith(SpringTestContextExtension.class)
public class DeferHttpSessionXmlConfigTests {

	private static final String CONFIG_LOCATION_PREFIX = "classpath:org/springframework/security/config/http/DeferHttpSessionTests";

	@Autowired
	FilterChainProxy springSecurityFilterChain;

	@Autowired
	private Service service;

	public final SpringTestContext spring = new SpringTestContext(this);

	@Test
	public void explicitDeferHttpSession() throws Exception {
		this.spring.configLocations(xml("Explicit")).autowire();

		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/");
		MockHttpServletRequest mockRequest = spy(request);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain chain = (httpRequest, httpResponse) -> httpResponse.getWriter().write(this.service.getMessage());

		this.springSecurityFilterChain.doFilter(mockRequest, response, chain);

		verify(mockRequest, never()).isRequestedSessionIdValid();
		verify(mockRequest, never()).changeSessionId();
		verify(mockRequest, never()).getSession(anyBoolean());
		verify(mockRequest, never()).getSession();
	}

	private static String xml(String configName) {
		return CONFIG_LOCATION_PREFIX + "-" + configName + ".xml";
	}

	public static class Service {

		@PreAuthorize("permitAll")
		public String getMessage() {
			return "message";
		}

	}

}
