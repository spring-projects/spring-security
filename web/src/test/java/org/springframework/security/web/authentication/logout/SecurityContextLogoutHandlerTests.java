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

package org.springframework.security.web.authentication.logout;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Rob Winch
 *
 */
public class SecurityContextLogoutHandlerTests {

	private MockHttpServletRequest request;

	private MockHttpServletResponse response;

	private SecurityContextLogoutHandler handler;

	@BeforeEach
	public void setUp() {
		this.request = new MockHttpServletRequest();
		this.response = new MockHttpServletResponse();
		this.handler = new SecurityContextLogoutHandler();
		SecurityContext context = SecurityContextHolder.createEmptyContext();
		context.setAuthentication(
				new TestingAuthenticationToken("user", "password", AuthorityUtils.createAuthorityList("ROLE_USER")));
		SecurityContextHolder.setContext(context);
	}

	@AfterEach
	public void tearDown() {
		SecurityContextHolder.clearContext();
	}

	// SEC-2025
	@Test
	public void clearsAuthentication() {
		SecurityContext beforeContext = SecurityContextHolder.getContext();
		this.handler.logout(this.request, this.response, SecurityContextHolder.getContext().getAuthentication());
		assertThat(beforeContext.getAuthentication()).isNull();
	}

	@Test
	public void disableClearsAuthentication() {
		this.handler.setClearAuthentication(false);
		SecurityContext beforeContext = SecurityContextHolder.getContext();
		Authentication beforeAuthentication = beforeContext.getAuthentication();
		this.handler.logout(this.request, this.response, SecurityContextHolder.getContext().getAuthentication());
		assertThat(beforeContext.getAuthentication()).isNotNull();
		assertThat(beforeContext.getAuthentication()).isSameAs(beforeAuthentication);
	}

}
