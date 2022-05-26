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

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.stubbing.Answer;

import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

/**
 * Tests {@link UsernamePasswordAuthenticationFilter}.
 *
 * @author Ben Alex
 */
public class UsernamePasswordAuthenticationFilterTests {

	@Test
	public void testNormalOperation() {
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/");
		request.addParameter(UsernamePasswordAuthenticationFilter.SPRING_SECURITY_FORM_USERNAME_KEY, "rod");
		request.addParameter(UsernamePasswordAuthenticationFilter.SPRING_SECURITY_FORM_PASSWORD_KEY, "koala");
		UsernamePasswordAuthenticationFilter filter = new UsernamePasswordAuthenticationFilter();
		filter.setAuthenticationManager(createAuthenticationManager());
		// filter.init(null);
		Authentication result = filter.attemptAuthentication(request, new MockHttpServletResponse());
		assertThat(result != null).isTrue();
		assertThat(((WebAuthenticationDetails) result.getDetails()).getRemoteAddress()).isEqualTo("127.0.0.1");
	}

	@Test
	public void testConstructorInjectionOfAuthenticationManager() {
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/");
		request.addParameter(UsernamePasswordAuthenticationFilter.SPRING_SECURITY_FORM_USERNAME_KEY, "rod");
		request.addParameter(UsernamePasswordAuthenticationFilter.SPRING_SECURITY_FORM_PASSWORD_KEY, "dokdo");
		UsernamePasswordAuthenticationFilter filter = new UsernamePasswordAuthenticationFilter(
				createAuthenticationManager());
		Authentication result = filter.attemptAuthentication(request, new MockHttpServletResponse());
		assertThat(result).isNotNull();
	}

	@Test
	public void testNullPasswordHandledGracefully() {
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/");
		request.addParameter(UsernamePasswordAuthenticationFilter.SPRING_SECURITY_FORM_USERNAME_KEY, "rod");
		UsernamePasswordAuthenticationFilter filter = new UsernamePasswordAuthenticationFilter();
		filter.setAuthenticationManager(createAuthenticationManager());
		assertThat(filter.attemptAuthentication(request, new MockHttpServletResponse())).isNotNull();
	}

	@Test
	public void testNullUsernameHandledGracefully() {
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/");
		request.addParameter(UsernamePasswordAuthenticationFilter.SPRING_SECURITY_FORM_PASSWORD_KEY, "koala");
		UsernamePasswordAuthenticationFilter filter = new UsernamePasswordAuthenticationFilter();
		filter.setAuthenticationManager(createAuthenticationManager());
		assertThat(filter.attemptAuthentication(request, new MockHttpServletResponse())).isNotNull();
	}

	@Test
	public void testUsingDifferentParameterNamesWorksAsExpected() {
		UsernamePasswordAuthenticationFilter filter = new UsernamePasswordAuthenticationFilter();
		filter.setAuthenticationManager(createAuthenticationManager());
		filter.setUsernameParameter("x");
		filter.setPasswordParameter("y");
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/");
		request.addParameter("x", "rod");
		request.addParameter("y", "koala");
		Authentication result = filter.attemptAuthentication(request, new MockHttpServletResponse());
		assertThat(result).isNotNull();
		assertThat(((WebAuthenticationDetails) result.getDetails()).getRemoteAddress()).isEqualTo("127.0.0.1");
	}

	@Test
	public void testSpacesAreTrimmedCorrectlyFromUsername() {
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/");
		request.addParameter(UsernamePasswordAuthenticationFilter.SPRING_SECURITY_FORM_USERNAME_KEY, " rod ");
		request.addParameter(UsernamePasswordAuthenticationFilter.SPRING_SECURITY_FORM_PASSWORD_KEY, "koala");
		UsernamePasswordAuthenticationFilter filter = new UsernamePasswordAuthenticationFilter();
		filter.setAuthenticationManager(createAuthenticationManager());
		Authentication result = filter.attemptAuthentication(request, new MockHttpServletResponse());
		assertThat(result.getName()).isEqualTo("rod");
	}

	@Test
	public void testFailedAuthenticationThrowsException() {
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/");
		request.addParameter(UsernamePasswordAuthenticationFilter.SPRING_SECURITY_FORM_USERNAME_KEY, "rod");
		UsernamePasswordAuthenticationFilter filter = new UsernamePasswordAuthenticationFilter();
		AuthenticationManager am = mock(AuthenticationManager.class);
		given(am.authenticate(any(Authentication.class))).willThrow(new BadCredentialsException(""));
		filter.setAuthenticationManager(am);
		assertThatExceptionOfType(AuthenticationException.class)
				.isThrownBy(() -> filter.attemptAuthentication(request, new MockHttpServletResponse()));
	}

	@Test
	public void testSecurityContextHolderStrategyUsed() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/login");
		request.setServletPath("/login");
		request.addParameter(UsernamePasswordAuthenticationFilter.SPRING_SECURITY_FORM_USERNAME_KEY, "rod");
		request.addParameter(UsernamePasswordAuthenticationFilter.SPRING_SECURITY_FORM_PASSWORD_KEY, "koala");
		UsernamePasswordAuthenticationFilter filter = new UsernamePasswordAuthenticationFilter();
		filter.setAuthenticationManager(createAuthenticationManager());
		SecurityContextHolderStrategy strategy = spy(SecurityContextHolder.getContextHolderStrategy());
		filter.setSecurityContextHolderStrategy(strategy);
		filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());
		ArgumentCaptor<SecurityContext> captor = ArgumentCaptor.forClass(SecurityContext.class);
		verify(strategy).setContext(captor.capture());
		assertThat(captor.getValue().getAuthentication()).isInstanceOf(UsernamePasswordAuthenticationToken.class);
	}

	/**
	 * SEC-571
	 */
	@Test
	public void noSessionIsCreatedIfAllowSessionCreationIsFalse() {
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
		given(am.authenticate(any(Authentication.class)))
				.willAnswer((Answer<Authentication>) (invocation) -> (Authentication) invocation.getArguments()[0]);
		return am;
	}

}
