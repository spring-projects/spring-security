/*
 * Copyright 2004-2016 the original author or authors.
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

package org.springframework.security.web.access;

import java.io.IOException;
import java.util.Locale;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.MockPortResolver;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.RememberMeAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.willThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyZeroInteractions;

/**
 * Tests {@link ExceptionTranslationFilter}.
 *
 * @author Ben Alex
 */
public class ExceptionTranslationFilterTests {

	@After
	@Before
	public void clearContext() {
		SecurityContextHolder.clearContext();
	}

	private static String getSavedRequestUrl(HttpServletRequest request) {
		HttpSession session = request.getSession(false);
		if (session == null) {
			return null;
		}
		HttpSessionRequestCache rc = new HttpSessionRequestCache();
		SavedRequest sr = rc.getRequest(request, new MockHttpServletResponse());
		return sr.getRedirectUrl();
	}

	@Test
	public void testAccessDeniedWhenAnonymous() throws Exception {
		// Setup our HTTP request
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setServletPath("/secure/page.html");
		request.setServerPort(80);
		request.setScheme("http");
		request.setServerName("localhost");
		request.setContextPath("/mycontext");
		request.setRequestURI("/mycontext/secure/page.html");
		// Setup the FilterChain to thrown an access denied exception
		FilterChain fc = mock(FilterChain.class);
		willThrow(new AccessDeniedException("")).given(fc).doFilter(any(HttpServletRequest.class),
				any(HttpServletResponse.class));
		// Setup SecurityContextHolder, as filter needs to check if user is
		// anonymous
		SecurityContextHolder.getContext().setAuthentication(
				new AnonymousAuthenticationToken("ignored", "ignored", AuthorityUtils.createAuthorityList("IGNORED")));
		// Test
		ExceptionTranslationFilter filter = new ExceptionTranslationFilter(this.mockEntryPoint);
		filter.setAuthenticationTrustResolver(new AuthenticationTrustResolverImpl());
		assertThat(filter.getAuthenticationTrustResolver()).isNotNull();
		MockHttpServletResponse response = new MockHttpServletResponse();
		filter.doFilter(request, response, fc);
		assertThat(response.getRedirectedUrl()).isEqualTo("/mycontext/login.jsp");
		assertThat(getSavedRequestUrl(request)).isEqualTo("http://localhost/mycontext/secure/page.html");
	}

	@Test
	public void testAccessDeniedWithRememberMe() throws Exception {
		// Setup our HTTP request
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setServletPath("/secure/page.html");
		request.setServerPort(80);
		request.setScheme("http");
		request.setServerName("localhost");
		request.setContextPath("/mycontext");
		request.setRequestURI("/mycontext/secure/page.html");
		// Setup the FilterChain to thrown an access denied exception
		FilterChain fc = mock(FilterChain.class);
		willThrow(new AccessDeniedException("")).given(fc).doFilter(any(HttpServletRequest.class),
				any(HttpServletResponse.class));
		// Setup SecurityContextHolder, as filter needs to check if user is remembered
		SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
		securityContext.setAuthentication(
				new RememberMeAuthenticationToken("ignored", "ignored", AuthorityUtils.createAuthorityList("IGNORED")));
		SecurityContextHolder.setContext(securityContext);
		// Test
		ExceptionTranslationFilter filter = new ExceptionTranslationFilter(this.mockEntryPoint);
		MockHttpServletResponse response = new MockHttpServletResponse();
		filter.doFilter(request, response, fc);
		assertThat(response.getRedirectedUrl()).isEqualTo("/mycontext/login.jsp");
		assertThat(getSavedRequestUrl(request)).isEqualTo("http://localhost/mycontext/secure/page.html");
	}

	@Test
	public void testAccessDeniedWhenNonAnonymous() throws Exception {
		// Setup our HTTP request
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setServletPath("/secure/page.html");
		// Setup the FilterChain to thrown an access denied exception
		FilterChain fc = mock(FilterChain.class);
		willThrow(new AccessDeniedException("")).given(fc).doFilter(any(HttpServletRequest.class),
				any(HttpServletResponse.class));
		// Setup SecurityContextHolder, as filter needs to check if user is
		// anonymous
		SecurityContextHolder.clearContext();
		// Setup a new AccessDeniedHandlerImpl that will do a "forward"
		AccessDeniedHandlerImpl adh = new AccessDeniedHandlerImpl();
		adh.setErrorPage("/error.jsp");
		// Test
		ExceptionTranslationFilter filter = new ExceptionTranslationFilter(this.mockEntryPoint);
		filter.setAccessDeniedHandler(adh);
		MockHttpServletResponse response = new MockHttpServletResponse();
		filter.doFilter(request, response, fc);
		assertThat(response.getStatus()).isEqualTo(403);
		assertThat(request.getAttribute(WebAttributes.ACCESS_DENIED_403))
				.isExactlyInstanceOf(AccessDeniedException.class);
	}

	@Test
	public void testLocalizedErrorMessages() throws Exception {
		// Setup our HTTP request
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setServletPath("/secure/page.html");
		// Setup the FilterChain to thrown an access denied exception
		FilterChain fc = mock(FilterChain.class);
		willThrow(new AccessDeniedException("")).given(fc).doFilter(any(HttpServletRequest.class),
				any(HttpServletResponse.class));
		// Setup SecurityContextHolder, as filter needs to check if user is
		// anonymous
		SecurityContextHolder.getContext().setAuthentication(
				new AnonymousAuthenticationToken("ignored", "ignored", AuthorityUtils.createAuthorityList("IGNORED")));
		// Test
		ExceptionTranslationFilter filter = new ExceptionTranslationFilter(
				(req, res, ae) -> res.sendError(403, ae.getMessage()));
		filter.setAuthenticationTrustResolver(new AuthenticationTrustResolverImpl());
		assertThat(filter.getAuthenticationTrustResolver()).isNotNull();
		LocaleContextHolder.setDefaultLocale(Locale.GERMAN);
		MockHttpServletResponse response = new MockHttpServletResponse();
		filter.doFilter(request, response, fc);
		assertThat(response.getErrorMessage())
				.isEqualTo("Vollst\u00e4ndige Authentifikation wird ben\u00f6tigt um auf diese Resource zuzugreifen");
	}

	@Test
	public void redirectedToLoginFormAndSessionShowsOriginalTargetWhenAuthenticationException() throws Exception {
		// Setup our HTTP request
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setServletPath("/secure/page.html");
		request.setServerPort(80);
		request.setScheme("http");
		request.setServerName("localhost");
		request.setContextPath("/mycontext");
		request.setRequestURI("/mycontext/secure/page.html");
		// Setup the FilterChain to thrown an authentication failure exception
		FilterChain fc = mock(FilterChain.class);
		willThrow(new BadCredentialsException("")).given(fc).doFilter(any(HttpServletRequest.class),
				any(HttpServletResponse.class));
		// Test
		ExceptionTranslationFilter filter = new ExceptionTranslationFilter(this.mockEntryPoint);
		filter.afterPropertiesSet();
		MockHttpServletResponse response = new MockHttpServletResponse();
		filter.doFilter(request, response, fc);
		assertThat(response.getRedirectedUrl()).isEqualTo("/mycontext/login.jsp");
		assertThat(getSavedRequestUrl(request)).isEqualTo("http://localhost/mycontext/secure/page.html");
	}

	@Test
	public void redirectedToLoginFormAndSessionShowsOriginalTargetWithExoticPortWhenAuthenticationException()
			throws Exception {
		// Setup our HTTP request
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setServletPath("/secure/page.html");
		request.setServerPort(8080);
		request.setScheme("http");
		request.setServerName("localhost");
		request.setContextPath("/mycontext");
		request.setRequestURI("/mycontext/secure/page.html");
		// Setup the FilterChain to thrown an authentication failure exception
		FilterChain fc = mock(FilterChain.class);
		willThrow(new BadCredentialsException("")).given(fc).doFilter(any(HttpServletRequest.class),
				any(HttpServletResponse.class));
		// Test
		HttpSessionRequestCache requestCache = new HttpSessionRequestCache();
		ExceptionTranslationFilter filter = new ExceptionTranslationFilter(this.mockEntryPoint, requestCache);
		requestCache.setPortResolver(new MockPortResolver(8080, 8443));
		filter.afterPropertiesSet();
		MockHttpServletResponse response = new MockHttpServletResponse();
		filter.doFilter(request, response, fc);
		assertThat(response.getRedirectedUrl()).isEqualTo("/mycontext/login.jsp");
		assertThat(getSavedRequestUrl(request)).isEqualTo("http://localhost:8080/mycontext/secure/page.html");
	}

	@Test
	public void startupDetectsMissingAuthenticationEntryPoint() {
		assertThatIllegalArgumentException().isThrownBy(() -> new ExceptionTranslationFilter(null));
	}

	@Test
	public void startupDetectsMissingRequestCache() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new ExceptionTranslationFilter(this.mockEntryPoint, null));
	}

	@Test
	public void successfulAccessGrant() throws Exception {
		// Setup our HTTP request
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setServletPath("/secure/page.html");
		// Test
		ExceptionTranslationFilter filter = new ExceptionTranslationFilter(this.mockEntryPoint);
		assertThat(filter.getAuthenticationEntryPoint()).isSameAs(this.mockEntryPoint);
		MockHttpServletResponse response = new MockHttpServletResponse();
		filter.doFilter(request, response, mock(FilterChain.class));
	}

	@Test
	public void thrownIOExceptionServletExceptionAndRuntimeExceptionsAreRethrown() throws Exception {
		ExceptionTranslationFilter filter = new ExceptionTranslationFilter(this.mockEntryPoint);
		filter.afterPropertiesSet();
		Exception[] exceptions = { new IOException(), new ServletException(), new RuntimeException() };
		for (Exception exception : exceptions) {
			FilterChain fc = mock(FilterChain.class);
			willThrow(exception).given(fc).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
			assertThatExceptionOfType(Exception.class)
					.isThrownBy(() -> filter.doFilter(new MockHttpServletRequest(), new MockHttpServletResponse(), fc))
					.isSameAs(exception);
		}
	}

	@Test
	public void doFilterWhenResponseCommittedThenRethrowsException() {
		this.mockEntryPoint = mock(AuthenticationEntryPoint.class);
		FilterChain chain = (request, response) -> {
			HttpServletResponse httpResponse = (HttpServletResponse) response;
			httpResponse.sendError(HttpServletResponse.SC_BAD_REQUEST);
			throw new AccessDeniedException("Denied");
		};
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		ExceptionTranslationFilter filter = new ExceptionTranslationFilter(this.mockEntryPoint);
		assertThatExceptionOfType(ServletException.class).isThrownBy(() -> filter.doFilter(request, response, chain))
				.withCauseInstanceOf(AccessDeniedException.class);
		verifyZeroInteractions(this.mockEntryPoint);
	}

	private AuthenticationEntryPoint mockEntryPoint = (request, response, authException) -> response
			.sendRedirect(request.getContextPath() + "/login.jsp");

}
