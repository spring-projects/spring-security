/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.web.authentication;

import static org.mockito.Mockito.*;
import static org.assertj.core.api.Assertions.*;

import javax.servlet.ServletException;

import org.junit.Test;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

/**
 * Tests {@link UsernamePasswordAuthenticationFilter}.
 *
 * @author Ben Alex
 */
public class UsernamePasswordAuthenticationFilterTests {
	// ~ Methods
	// ========================================================================================================

	@Test
	public void testNormalOperation() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/");
		request.addParameter(
				UsernamePasswordAuthenticationFilter.SPRING_SECURITY_FORM_USERNAME_KEY,
				"rod");
		request.addParameter(
				UsernamePasswordAuthenticationFilter.SPRING_SECURITY_FORM_PASSWORD_KEY,
				"koala");

		UsernamePasswordAuthenticationFilter filter = new UsernamePasswordAuthenticationFilter();
		filter.setAuthenticationManager(createAuthenticationManager());
		// filter.init(null);

		Authentication result = filter.attemptAuthentication(request,
				new MockHttpServletResponse());
		assertThat(result != null).isTrue();
		assertThat(((WebAuthenticationDetails) result.getDetails()).getRemoteAddress()).isEqualTo("127.0.0.1");
	}

	@Test
	public void testNullPasswordHandledGracefully() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/");
		request.addParameter(
				UsernamePasswordAuthenticationFilter.SPRING_SECURITY_FORM_USERNAME_KEY,
				"rod");

		UsernamePasswordAuthenticationFilter filter = new UsernamePasswordAuthenticationFilter();
		filter.setAuthenticationManager(createAuthenticationManager());
		assertThat(filter
				.attemptAuthentication(request, new MockHttpServletResponse())).isNotNull();
	}

	@Test
	public void testNullUsernameHandledGracefully() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/");
		request.addParameter(
				UsernamePasswordAuthenticationFilter.SPRING_SECURITY_FORM_PASSWORD_KEY,
				"koala");

		UsernamePasswordAuthenticationFilter filter = new UsernamePasswordAuthenticationFilter();
		filter.setAuthenticationManager(createAuthenticationManager());
		assertThat(filter
				.attemptAuthentication(request, new MockHttpServletResponse())).isNotNull();
	}

	@Test
	public void testUsingDifferentParameterNamesWorksAsExpected() throws ServletException {
		UsernamePasswordAuthenticationFilter filter = new UsernamePasswordAuthenticationFilter();
		filter.setAuthenticationManager(createAuthenticationManager());
		filter.setUsernameParameter("x");
		filter.setPasswordParameter("y");

		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/");
		request.addParameter("x", "rod");
		request.addParameter("y", "koala");

		Authentication result = filter.attemptAuthentication(request,
				new MockHttpServletResponse());
		assertThat(result).isNotNull();
		assertThat(((WebAuthenticationDetails) result.getDetails()).getRemoteAddress()).isEqualTo("127.0.0.1");
	}

	@Test
	public void testSpacesAreTrimmedCorrectlyFromUsername() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/");
		request.addParameter(
				UsernamePasswordAuthenticationFilter.SPRING_SECURITY_FORM_USERNAME_KEY,
				" rod ");
		request.addParameter(
				UsernamePasswordAuthenticationFilter.SPRING_SECURITY_FORM_PASSWORD_KEY,
				"koala");

		UsernamePasswordAuthenticationFilter filter = new UsernamePasswordAuthenticationFilter();
		filter.setAuthenticationManager(createAuthenticationManager());

		Authentication result = filter.attemptAuthentication(request,
				new MockHttpServletResponse());
		assertThat(result.getName()).isEqualTo("rod");
	}

	@Test
	public void testFailedAuthenticationThrowsException() {
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/");
		request.addParameter(
				UsernamePasswordAuthenticationFilter.SPRING_SECURITY_FORM_USERNAME_KEY,
				"rod");
		UsernamePasswordAuthenticationFilter filter = new UsernamePasswordAuthenticationFilter();
		AuthenticationManager am = mock(AuthenticationManager.class);
		when(am.authenticate(any(Authentication.class))).thenThrow(
				new BadCredentialsException(""));
		filter.setAuthenticationManager(am);

		try {
			filter.attemptAuthentication(request, new MockHttpServletResponse());
			fail("Expected AuthenticationException");
		}
		catch (AuthenticationException e) {
		}
	}

	/**
	 * SEC-571
	 */
	@Test
	public void noSessionIsCreatedIfAllowSessionCreationIsFalse() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setMethod("POST");

		UsernamePasswordAuthenticationFilter filter = new UsernamePasswordAuthenticationFilter();
		filter.setAllowSessionCreation(false);
		filter.setAuthenticationManager(createAuthenticationManager());

		filter.attemptAuthentication(request, new MockHttpServletResponse());

		assertThat(request.getSession(false)).isNull();
	}

	private AuthenticationManager createAuthenticationManager() {
		AuthenticationManager am = mock(AuthenticationManager.class);
		when(am.authenticate(any(Authentication.class))).thenAnswer(
				new Answer<Authentication>() {
					public Authentication answer(InvocationOnMock invocation)
							throws Throwable {
						return (Authentication) invocation.getArguments()[0];
					}
				});

		return am;
	}

}
