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
package org.springframework.security.web.authentication.preauth;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.stubbing.Answer;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 *
 * @author Milan Sevcik
 */
public class RequestAttributeAuthenticationFilterTests {

	@After
	@Before
	public void clearContext() {
		SecurityContextHolder.clearContext();
	}

	@Test(expected = PreAuthenticatedCredentialsNotFoundException.class)
	public void rejectsMissingHeader() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		MockFilterChain chain = new MockFilterChain();
		RequestAttributeAuthenticationFilter filter = new RequestAttributeAuthenticationFilter();

		filter.doFilter(request, response, chain);
	}

	@Test
	public void defaultsToUsingSiteminderHeader() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setAttribute("REMOTE_USER", "cat");
		MockHttpServletResponse response = new MockHttpServletResponse();
		MockFilterChain chain = new MockFilterChain();
		RequestAttributeAuthenticationFilter filter = new RequestAttributeAuthenticationFilter();
		filter.setAuthenticationManager(createAuthenticationManager());

		filter.doFilter(request, response, chain);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
		assertThat(SecurityContextHolder.getContext().getAuthentication().getName())
				.isEqualTo("cat");
		assertThat(
				SecurityContextHolder.getContext().getAuthentication().getCredentials())
						.isEqualTo("N/A");
	}

	@Test
	public void alternativeHeaderNameIsSupported() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setAttribute("myUsernameVariable", "wolfman");
		MockHttpServletResponse response = new MockHttpServletResponse();
		MockFilterChain chain = new MockFilterChain();
		RequestAttributeAuthenticationFilter filter = new RequestAttributeAuthenticationFilter();
		filter.setAuthenticationManager(createAuthenticationManager());
		filter.setPrincipalEnvironmentVariable("myUsernameVariable");

		filter.doFilter(request, response, chain);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
		assertThat(SecurityContextHolder.getContext().getAuthentication().getName())
				.isEqualTo("wolfman");
	}

	@Test
	public void credentialsAreRetrievedIfHeaderNameIsSet() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		MockFilterChain chain = new MockFilterChain();
		RequestAttributeAuthenticationFilter filter = new RequestAttributeAuthenticationFilter();
		filter.setAuthenticationManager(createAuthenticationManager());
		filter.setCredentialsEnvironmentVariable("myCredentialsVariable");
		request.setAttribute("REMOTE_USER", "cat");
		request.setAttribute("myCredentialsVariable", "catspassword");

		filter.doFilter(request, response, chain);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
		assertThat(
				SecurityContextHolder.getContext().getAuthentication().getCredentials())
						.isEqualTo("catspassword");
	}

	@Test
	public void userIsReauthenticatedIfPrincipalChangesAndCheckForPrincipalChangesIsSet()
			throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		RequestAttributeAuthenticationFilter filter = new RequestAttributeAuthenticationFilter();
		filter.setAuthenticationManager(createAuthenticationManager());
		filter.setCheckForPrincipalChanges(true);
		request.setAttribute("REMOTE_USER", "cat");
		filter.doFilter(request, response, new MockFilterChain());
		request = new MockHttpServletRequest();
		request.setAttribute("REMOTE_USER", "dog");
		filter.doFilter(request, response, new MockFilterChain());
		Authentication dog = SecurityContextHolder.getContext().getAuthentication();
		assertThat(dog).isNotNull();
		assertThat(dog.getName()).isEqualTo("dog");
		// Make sure authentication doesn't occur every time (i.e. if the variable
		// *doesn't*
		// change)
		filter.setAuthenticationManager(mock(AuthenticationManager.class));
		filter.doFilter(request, response, new MockFilterChain());
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(dog);
	}

	@Test(expected = PreAuthenticatedCredentialsNotFoundException.class)
	public void missingHeaderCausesException() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		MockFilterChain chain = new MockFilterChain();
		RequestAttributeAuthenticationFilter filter = new RequestAttributeAuthenticationFilter();
		filter.setAuthenticationManager(createAuthenticationManager());

		filter.doFilter(request, response, chain);
	}

	@Test
	public void missingHeaderIsIgnoredIfExceptionIfHeaderMissingIsFalse()
			throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		MockFilterChain chain = new MockFilterChain();
		RequestAttributeAuthenticationFilter filter = new RequestAttributeAuthenticationFilter();
		filter.setExceptionIfVariableMissing(false);
		filter.setAuthenticationManager(createAuthenticationManager());
		filter.doFilter(request, response, chain);
	}

	/**
	 * Create an authentication manager which returns the passed in object.
	 */
	private AuthenticationManager createAuthenticationManager() {
		AuthenticationManager am = mock(AuthenticationManager.class);
		when(am.authenticate(any(Authentication.class)))
				.thenAnswer((Answer<Authentication>) invocation -> (Authentication) invocation.getArguments()[0]);

		return am;
	}
}
