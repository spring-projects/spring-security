/*
 * Copyright 2002-2014 the original author or authors.
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
package org.springframework.security.test.web.servlet.request;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.www.DigestAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.DigestAuthenticationFilter;

import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.digest;

public class SecurityMockMvcRequestPostProcessorsDigestTests {

	private DigestAuthenticationFilter filter;
	private MockHttpServletRequest request;

	private String username;

	private String password;

	private DigestAuthenticationEntryPoint entryPoint;

	@Before
	public void setup() {
		this.password = "password";
		request = new MockHttpServletRequest();

		entryPoint = new DigestAuthenticationEntryPoint();
		entryPoint.setKey("key");
		entryPoint.setRealmName("Spring Security");
		filter = new DigestAuthenticationFilter();
		filter.setUserDetailsService(username -> new User(username, password, AuthorityUtils
				.createAuthorityList("ROLE_USER")));
		filter.setAuthenticationEntryPoint(entryPoint);
		filter.afterPropertiesSet();
	}

	@After
	public void cleanup() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void digestWithFilter() throws Exception {
		MockHttpServletRequest postProcessedRequest = digest()
				.postProcessRequest(request);

		assertThat(extractUser()).isEqualTo("user");
	}

	@Test
	public void digestWithFilterCustomUsername() throws Exception {
		String username = "admin";
		MockHttpServletRequest postProcessedRequest = digest(username)
				.postProcessRequest(request);

		assertThat(extractUser()).isEqualTo(username);
	}

	@Test
	public void digestWithFilterCustomPassword() throws Exception {
		String username = "custom";
		password = "secret";
		MockHttpServletRequest postProcessedRequest = digest(username).password(password)
				.postProcessRequest(request);

		assertThat(extractUser()).isEqualTo(username);
	}

	@Test
	public void digestWithFilterCustomRealm() throws Exception {
		String username = "admin";
		entryPoint.setRealmName("Custom");
		MockHttpServletRequest postProcessedRequest = digest(username).realm(
				entryPoint.getRealmName()).postProcessRequest(request);

		assertThat(extractUser()).isEqualTo(username);
	}

	@Test
	public void digestWithFilterFails() throws Exception {
		String username = "admin";
		MockHttpServletRequest postProcessedRequest = digest(username).realm("Invalid")
				.postProcessRequest(request);

		assertThat(extractUser()).isNull();
	}

	private String extractUser() throws IOException, ServletException {
		filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain() {
			@Override
			public void doFilter(ServletRequest request, ServletResponse response) {
				Authentication authentication = SecurityContextHolder.getContext()
						.getAuthentication();
				username = authentication == null ? null : authentication.getName();
			}
		});
		return username;
	}
}
