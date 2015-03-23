/*
 * Copyright 2002-2014 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.test.web.servlet.request;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.verify;
import static org.fest.assertions.Assertions.assertThat;
import static org.powermock.api.mockito.PowerMockito.spy;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.doReturn;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.logout;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.test.web.support.WebTestUtils;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.DefaultCsrfToken;

@RunWith(PowerMockRunner.class)
@PrepareForTest({ WebTestUtils.class, SecurityMockMvcRequestBuildersFormLogoutTests.class })
public class SecurityMockMvcRequestBuildersFormLogoutTests {
	@Mock
	private CsrfTokenRepository repository;
	private DefaultCsrfToken token;
	private MockServletContext servletContext;

	@Before
	public void setup() {
		token = new DefaultCsrfToken("header", "param", "token");
		servletContext = new MockServletContext();
	}

	@Test
	public void defaults() throws Exception {
		mockWebTestUtils();
		MockHttpServletRequest request = logout().buildRequest(servletContext);

		assertThat(request.getMethod()).isEqualTo("POST");
		assertThat(request.getParameter(token.getParameterName())).isEqualTo(
				token.getToken());
		assertThat(request.getRequestURI()).isEqualTo("/logout");
		verify(repository).saveToken(eq(token), any(HttpServletRequest.class),
				any(HttpServletResponse.class));
	}

	@Test
	public void custom() throws Exception {
		mockWebTestUtils();
		MockHttpServletRequest request = logout("/admin/logout").buildRequest(
				servletContext);

		assertThat(request.getMethod()).isEqualTo("POST");
		assertThat(request.getParameter(token.getParameterName())).isEqualTo(
				token.getToken());
		assertThat(request.getRequestURI()).isEqualTo("/admin/logout");
		verify(repository).saveToken(eq(token), any(HttpServletRequest.class),
				any(HttpServletResponse.class));
	}

	private void mockWebTestUtils() throws Exception {
		spy(WebTestUtils.class);
		doReturn(repository).when(WebTestUtils.class, "getCsrfTokenRepository",
				any(HttpServletRequest.class));
		when(repository.generateToken(any(HttpServletRequest.class))).thenReturn(token);
	}
}
