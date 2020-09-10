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

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.stubbing.Answer;

import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.authentication.ForwardAuthenticationFailureHandler;
import org.springframework.security.web.authentication.ForwardAuthenticationSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;

/**
 * @author Rob Winch
 * @author Tadaya Tsuyukubo
 *
 */
public class AbstractPreAuthenticatedProcessingFilterTests {

	private AbstractPreAuthenticatedProcessingFilter filter;

	@Before
	public void createFilter() {
		this.filter = new AbstractPreAuthenticatedProcessingFilter() {
			@Override
			protected Object getPreAuthenticatedCredentials(HttpServletRequest request) {
				return "n/a";
			}

			@Override
			protected Object getPreAuthenticatedPrincipal(HttpServletRequest request) {
				return "doesntmatter";
			}
		};
		SecurityContextHolder.clearContext();
	}

	@After
	public void tearDown() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void filterChainProceedsOnFailedAuthenticationByDefault() throws Exception {
		AuthenticationManager am = mock(AuthenticationManager.class);
		given(am.authenticate(any(Authentication.class))).willThrow(new BadCredentialsException(""));
		this.filter.setAuthenticationManager(am);
		this.filter.afterPropertiesSet();
		this.filter.doFilter(new MockHttpServletRequest(), new MockHttpServletResponse(), mock(FilterChain.class));
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
	}

	/* SEC-881 */
	@Test(expected = BadCredentialsException.class)
	public void exceptionIsThrownOnFailedAuthenticationIfContinueFilterChainOnUnsuccessfulAuthenticationSetToFalse()
			throws Exception {
		AuthenticationManager am = mock(AuthenticationManager.class);
		given(am.authenticate(any(Authentication.class))).willThrow(new BadCredentialsException(""));
		this.filter.setContinueFilterChainOnUnsuccessfulAuthentication(false);
		this.filter.setAuthenticationManager(am);
		this.filter.afterPropertiesSet();
		this.filter.doFilter(new MockHttpServletRequest(), new MockHttpServletResponse(), mock(FilterChain.class));
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
	}

	@Test
	public void testAfterPropertiesSet() {
		ConcretePreAuthenticatedProcessingFilter filter = new ConcretePreAuthenticatedProcessingFilter();
		assertThatIllegalArgumentException().isThrownBy(filter::afterPropertiesSet);
	}

	// SEC-2045
	@Test
	public void testAfterPropertiesSetInvokesSuper() {
		ConcretePreAuthenticatedProcessingFilter filter = new ConcretePreAuthenticatedProcessingFilter();
		AuthenticationManager am = mock(AuthenticationManager.class);
		filter.setAuthenticationManager(am);
		filter.afterPropertiesSet();
		assertThat(filter.initFilterBeanInvoked).isTrue();
	}

	@Test
	public void testDoFilterAuthenticated() throws Exception {
		testDoFilter(true);
	}

	@Test
	public void testDoFilterUnauthenticated() throws Exception {
		testDoFilter(false);
	}

	// SEC-1968
	@Test
	public void nullPreAuthenticationClearsPreviousUser() throws Exception {
		SecurityContextHolder.getContext()
				.setAuthentication(new TestingAuthenticationToken("oldUser", "pass", "ROLE_USER"));
		ConcretePreAuthenticatedProcessingFilter filter = new ConcretePreAuthenticatedProcessingFilter();
		filter.principal = null;
		filter.setCheckForPrincipalChanges(true);
		filter.doFilter(new MockHttpServletRequest(), new MockHttpServletResponse(), new MockFilterChain());
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
	}

	@Test
	public void nullPreAuthenticationPerservesPreviousUserCheckPrincipalChangesFalse() throws Exception {
		TestingAuthenticationToken authentication = new TestingAuthenticationToken("oldUser", "pass", "ROLE_USER");
		SecurityContextHolder.getContext().setAuthentication(authentication);
		ConcretePreAuthenticatedProcessingFilter filter = new ConcretePreAuthenticatedProcessingFilter();
		filter.principal = null;
		filter.doFilter(new MockHttpServletRequest(), new MockHttpServletResponse(), new MockFilterChain());
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isEqualTo(authentication);
	}

	@Test
	public void requiresAuthenticationFalsePrincipalString() throws Exception {
		Object principal = "sameprincipal";
		SecurityContextHolder.getContext()
				.setAuthentication(new TestingAuthenticationToken(principal, "something", "ROLE_USER"));
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		MockFilterChain chain = new MockFilterChain();
		ConcretePreAuthenticatedProcessingFilter filter = new ConcretePreAuthenticatedProcessingFilter();
		filter.setCheckForPrincipalChanges(true);
		filter.principal = principal;
		AuthenticationManager am = mock(AuthenticationManager.class);
		filter.setAuthenticationManager(am);
		filter.afterPropertiesSet();
		filter.doFilter(request, response, chain);
		verifyZeroInteractions(am);
	}

	@Test
	public void requiresAuthenticationTruePrincipalString() throws Exception {
		Object currentPrincipal = "currentUser";
		TestingAuthenticationToken authRequest = new TestingAuthenticationToken(currentPrincipal, "something",
				"ROLE_USER");
		SecurityContextHolder.getContext().setAuthentication(authRequest);
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		MockFilterChain chain = new MockFilterChain();
		ConcretePreAuthenticatedProcessingFilter filter = new ConcretePreAuthenticatedProcessingFilter();
		filter.setCheckForPrincipalChanges(true);
		filter.principal = "newUser";
		AuthenticationManager am = mock(AuthenticationManager.class);
		filter.setAuthenticationManager(am);
		filter.afterPropertiesSet();
		filter.doFilter(request, response, chain);
		verify(am).authenticate(any(PreAuthenticatedAuthenticationToken.class));
	}

	@Test
	public void callsAuthenticationSuccessHandlerOnSuccessfulAuthentication() throws Exception {
		Object currentPrincipal = "currentUser";
		TestingAuthenticationToken authRequest = new TestingAuthenticationToken(currentPrincipal, "something",
				"ROLE_USER");
		SecurityContextHolder.getContext().setAuthentication(authRequest);
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		MockFilterChain chain = new MockFilterChain();
		ConcretePreAuthenticatedProcessingFilter filter = new ConcretePreAuthenticatedProcessingFilter();
		filter.setAuthenticationSuccessHandler(new ForwardAuthenticationSuccessHandler("/forwardUrl"));
		filter.setCheckForPrincipalChanges(true);
		filter.principal = "newUser";
		AuthenticationManager am = mock(AuthenticationManager.class);
		filter.setAuthenticationManager(am);
		filter.afterPropertiesSet();
		filter.doFilter(request, response, chain);
		verify(am).authenticate(any(PreAuthenticatedAuthenticationToken.class));
		assertThat(response.getForwardedUrl()).isEqualTo("/forwardUrl");
	}

	@Test
	public void callsAuthenticationFailureHandlerOnFailedAuthentication() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		MockFilterChain chain = new MockFilterChain();
		ConcretePreAuthenticatedProcessingFilter filter = new ConcretePreAuthenticatedProcessingFilter();
		filter.setAuthenticationFailureHandler(new ForwardAuthenticationFailureHandler("/forwardUrl"));
		filter.setCheckForPrincipalChanges(true);
		AuthenticationManager am = mock(AuthenticationManager.class);
		given(am.authenticate(any(PreAuthenticatedAuthenticationToken.class)))
				.willThrow(new PreAuthenticatedCredentialsNotFoundException("invalid"));
		filter.setAuthenticationManager(am);
		filter.afterPropertiesSet();
		filter.doFilter(request, response, chain);
		verify(am).authenticate(any(PreAuthenticatedAuthenticationToken.class));
		assertThat(response.getForwardedUrl()).isEqualTo("/forwardUrl");
		assertThat(request.getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION)).isNotNull();
	}

	// SEC-2078
	@Test
	public void requiresAuthenticationFalsePrincipalNotString() throws Exception {
		Object principal = new Object();
		SecurityContextHolder.getContext()
				.setAuthentication(new TestingAuthenticationToken(principal, "something", "ROLE_USER"));
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		MockFilterChain chain = new MockFilterChain();
		ConcretePreAuthenticatedProcessingFilter filter = new ConcretePreAuthenticatedProcessingFilter();
		filter.setCheckForPrincipalChanges(true);
		filter.principal = principal;
		AuthenticationManager am = mock(AuthenticationManager.class);
		filter.setAuthenticationManager(am);
		filter.afterPropertiesSet();
		filter.doFilter(request, response, chain);
		verifyZeroInteractions(am);
	}

	@Test
	public void requiresAuthenticationFalsePrincipalUser() throws Exception {
		User currentPrincipal = new User("user", "password", AuthorityUtils.createAuthorityList("ROLE_USER"));
		UsernamePasswordAuthenticationToken currentAuthentication = new UsernamePasswordAuthenticationToken(
				currentPrincipal, currentPrincipal.getPassword(), currentPrincipal.getAuthorities());
		SecurityContextHolder.getContext().setAuthentication(currentAuthentication);
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		MockFilterChain chain = new MockFilterChain();
		ConcretePreAuthenticatedProcessingFilter filter = new ConcretePreAuthenticatedProcessingFilter();
		filter.setCheckForPrincipalChanges(true);
		filter.principal = new User(currentPrincipal.getUsername(), currentPrincipal.getPassword(),
				AuthorityUtils.NO_AUTHORITIES);
		AuthenticationManager am = mock(AuthenticationManager.class);
		filter.setAuthenticationManager(am);
		filter.afterPropertiesSet();
		filter.doFilter(request, response, chain);
		verifyZeroInteractions(am);
	}

	@Test
	public void requiresAuthenticationTruePrincipalNotString() throws Exception {
		Object currentPrincipal = new Object();
		TestingAuthenticationToken authRequest = new TestingAuthenticationToken(currentPrincipal, "something",
				"ROLE_USER");
		SecurityContextHolder.getContext().setAuthentication(authRequest);
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		MockFilterChain chain = new MockFilterChain();
		ConcretePreAuthenticatedProcessingFilter filter = new ConcretePreAuthenticatedProcessingFilter();
		filter.setCheckForPrincipalChanges(true);
		filter.principal = new Object();
		AuthenticationManager am = mock(AuthenticationManager.class);
		filter.setAuthenticationManager(am);
		filter.afterPropertiesSet();
		filter.doFilter(request, response, chain);
		verify(am).authenticate(any(PreAuthenticatedAuthenticationToken.class));
	}

	@Test
	public void requiresAuthenticationOverridePrincipalChangedTrue() throws Exception {
		Object principal = new Object();
		SecurityContextHolder.getContext()
				.setAuthentication(new TestingAuthenticationToken(principal, "something", "ROLE_USER"));
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		MockFilterChain chain = new MockFilterChain();
		ConcretePreAuthenticatedProcessingFilter filter = new ConcretePreAuthenticatedProcessingFilter() {
			@Override
			protected boolean principalChanged(HttpServletRequest request, Authentication currentAuthentication) {
				return true;
			}
		};
		filter.setCheckForPrincipalChanges(true);
		filter.principal = principal;
		AuthenticationManager am = mock(AuthenticationManager.class);
		filter.setAuthenticationManager(am);
		filter.afterPropertiesSet();
		filter.doFilter(request, response, chain);
		verify(am).authenticate(any(PreAuthenticatedAuthenticationToken.class));
	}

	@Test
	public void requiresAuthenticationOverridePrincipalChangedFalse() throws Exception {
		Object principal = new Object();
		SecurityContextHolder.getContext()
				.setAuthentication(new TestingAuthenticationToken(principal, "something", "ROLE_USER"));
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		MockFilterChain chain = new MockFilterChain();
		ConcretePreAuthenticatedProcessingFilter filter = new ConcretePreAuthenticatedProcessingFilter() {
			@Override
			protected boolean principalChanged(HttpServletRequest request, Authentication currentAuthentication) {
				return false;
			}
		};
		filter.setCheckForPrincipalChanges(true);
		filter.principal = principal;
		AuthenticationManager am = mock(AuthenticationManager.class);
		filter.setAuthenticationManager(am);
		filter.afterPropertiesSet();
		filter.doFilter(request, response, chain);
		verifyZeroInteractions(am);
	}

	@Test
	public void requestNotMatchRequestMatcher() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		MockFilterChain chain = new MockFilterChain();
		ConcretePreAuthenticatedProcessingFilter filter = new ConcretePreAuthenticatedProcessingFilter();
		filter.setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher("/no-matching"));
		AuthenticationManager am = mock(AuthenticationManager.class);
		filter.setAuthenticationManager(am);
		filter.afterPropertiesSet();
		filter.doFilter(request, response, chain);
		verifyZeroInteractions(am);
	}

	@Test
	public void requestMatchesRequestMatcher() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		MockFilterChain chain = new MockFilterChain();
		ConcretePreAuthenticatedProcessingFilter filter = new ConcretePreAuthenticatedProcessingFilter();
		filter.setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher("/**"));
		AuthenticationManager am = mock(AuthenticationManager.class);
		filter.setAuthenticationManager(am);
		filter.afterPropertiesSet();
		filter.doFilter(request, response, chain);
		verify(am).authenticate(any(PreAuthenticatedAuthenticationToken.class));
	}

	private void testDoFilter(boolean grantAccess) throws Exception {
		MockHttpServletRequest req = new MockHttpServletRequest();
		MockHttpServletResponse res = new MockHttpServletResponse();
		getFilter(grantAccess).doFilter(req, res, new MockFilterChain());
		assertThat(null != SecurityContextHolder.getContext().getAuthentication()).isEqualTo(grantAccess);
	}

	private static ConcretePreAuthenticatedProcessingFilter getFilter(boolean grantAccess) {
		ConcretePreAuthenticatedProcessingFilter filter = new ConcretePreAuthenticatedProcessingFilter();
		AuthenticationManager am = mock(AuthenticationManager.class);
		if (!grantAccess) {
			given(am.authenticate(any(Authentication.class))).willThrow(new BadCredentialsException(""));
		}
		else {
			given(am.authenticate(any(Authentication.class)))
					.willAnswer((Answer<Authentication>) (invocation) -> (Authentication) invocation.getArguments()[0]);
		}
		filter.setAuthenticationManager(am);
		filter.afterPropertiesSet();
		return filter;
	}

	private static class ConcretePreAuthenticatedProcessingFilter extends AbstractPreAuthenticatedProcessingFilter {

		private Object principal = "testPrincipal";

		private boolean initFilterBeanInvoked;

		@Override
		protected Object getPreAuthenticatedPrincipal(HttpServletRequest httpRequest) {
			return this.principal;
		}

		@Override
		protected Object getPreAuthenticatedCredentials(HttpServletRequest httpRequest) {
			return "testCredentials";
		}

		@Override
		protected void initFilterBean() throws ServletException {
			super.initFilterBean();
			this.initFilterBeanInvoked = true;
		}

	}

}
