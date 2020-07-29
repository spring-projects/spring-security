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

package org.springframework.security.config.core;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import static org.assertj.core.api.Assertions.assertThat;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration
public class GrantedAuthorityDefaultsXmlTests {

	@Autowired
	FilterChainProxy springSecurityFilterChain;

	@Autowired
	MessageService messageService;

	MockHttpServletRequest request;

	MockHttpServletResponse response;

	MockFilterChain chain;

	@Before
	public void setup() {
		setup("USER");

		this.request = new MockHttpServletRequest("GET", "");
		this.request.setMethod("GET");
		this.response = new MockHttpServletResponse();
		this.chain = new MockFilterChain();
	}

	@After
	public void cleanup() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void doFilter() throws Exception {
		SecurityContext context = SecurityContextHolder.getContext();
		this.request.getSession().setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
				context);

		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);

		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
	}

	@Test
	public void doFilterDenied() throws Exception {
		setup("DENIED");

		SecurityContext context = SecurityContextHolder.getContext();
		this.request.getSession().setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
				context);

		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);

		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_FORBIDDEN);
	}

	@Test
	public void message() {
		this.messageService.getMessage();
	}

	@Test
	public void jsrMessage() {
		this.messageService.getJsrMessage();
	}

	@Test(expected = AccessDeniedException.class)
	public void messageDenied() {
		setup("DENIED");

		this.messageService.getMessage();
	}

	@Test(expected = AccessDeniedException.class)
	public void jsrMessageDenied() {
		setup("DENIED");

		this.messageService.getJsrMessage();
	}

	// SEC-2926
	@Test
	public void doFilterIsUserInRole() throws Exception {
		SecurityContext context = SecurityContextHolder.getContext();
		this.request.getSession().setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
				context);

		this.chain = new MockFilterChain() {

			@Override
			public void doFilter(ServletRequest request, ServletResponse response)
					throws IOException, ServletException {
				HttpServletRequest httpRequest = (HttpServletRequest) request;
				assertThat(httpRequest.isUserInRole("USER")).isTrue();
				assertThat(httpRequest.isUserInRole("INVALID")).isFalse();
				super.doFilter(request, response);
			}

		};

		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);

		assertThat(this.chain.getRequest()).isNotNull();
	}

	private void setup(String role) {
		TestingAuthenticationToken user = new TestingAuthenticationToken("user", "password", role);
		SecurityContextHolder.getContext().setAuthentication(user);
	}

}
