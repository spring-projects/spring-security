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

package org.springframework.security.web.access;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.MockPortResolver;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

/**
 * Tests {@link ExceptionTranslationFilter}.
 *
 * @author Ben Alex
 */
public class ExceptionTranslationFilterTests {

	@After
	@Before
	public void clearContext() throws Exception {
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
		request.setServerName("www.example.com");
		request.setContextPath("/mycontext");
		request.setRequestURI("/mycontext/secure/page.html");

		// Setup the FilterChain to thrown an access denied exception
		FilterChain fc = mock(FilterChain.class);
		doThrow(new AccessDeniedException("")).when(fc).doFilter(
				any(HttpServletRequest.class), any(HttpServletResponse.class));

		// Setup SecurityContextHolder, as filter needs to check if user is
		// anonymous
		SecurityContextHolder.getContext().setAuthentication(
				new AnonymousAuthenticationToken("ignored", "ignored", AuthorityUtils
						.createAuthorityList("IGNORED")));

		// Test
		ExceptionTranslationFilter filter = new ExceptionTranslationFilter(mockEntryPoint);
		filter.setAuthenticationTrustResolver(new AuthenticationTrustResolverImpl());
		assertThat(filter.getAuthenticationTrustResolver()).isNotNull();

		MockHttpServletResponse response = new MockHttpServletResponse();
		filter.doFilter(request, response, fc);
		assertThat(response.getRedirectedUrl()).isEqualTo("/mycontext/login.jsp");
		assertThat(getSavedRequestUrl(request)).isEqualTo("https://www.example.com/mycontext/secure/page.html");
	}

	@Test
	public void testAccessDeniedWhenNonAnonymous() throws Exception {
		// Setup our HTTP request
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setServletPath("/secure/page.html");

		// Setup the FilterChain to thrown an access denied exception
		FilterChain fc = mock(FilterChain.class);
		doThrow(new AccessDeniedException("")).when(fc).doFilter(
				any(HttpServletRequest.class), any(HttpServletResponse.class));

		// Setup SecurityContextHolder, as filter needs to check if user is
		// anonymous
		SecurityContextHolder.clearContext();

		// Setup a new AccessDeniedHandlerImpl that will do a "forward"
		AccessDeniedHandlerImpl adh = new AccessDeniedHandlerImpl();
		adh.setErrorPage("/error.jsp");

		// Test
		ExceptionTranslationFilter filter = new ExceptionTranslationFilter(mockEntryPoint);
		filter.setAccessDeniedHandler(adh);

		MockHttpServletResponse response = new MockHttpServletResponse();
		filter.doFilter(request, response, fc);
		assertThat(response.getStatus()).isEqualTo(403);
		assertThat(request.getAttribute(WebAttributes.ACCESS_DENIED_403)).isExactlyInstanceOf(AccessDeniedException.class);
	}

	@Test
	public void redirectedToLoginFormAndSessionShowsOriginalTargetWhenAuthenticationException()
			throws Exception {
		// Setup our HTTP request
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setServletPath("/secure/page.html");
		request.setServerPort(80);
		request.setScheme("http");
		request.setServerName("www.example.com");
		request.setContextPath("/mycontext");
		request.setRequestURI("/mycontext/secure/page.html");

		// Setup the FilterChain to thrown an authentication failure exception
		FilterChain fc = mock(FilterChain.class);
		doThrow(new BadCredentialsException("")).when(fc).doFilter(
				any(HttpServletRequest.class), any(HttpServletResponse.class));

		// Test
		ExceptionTranslationFilter filter = new ExceptionTranslationFilter(mockEntryPoint);
		filter.afterPropertiesSet();
		MockHttpServletResponse response = new MockHttpServletResponse();
		filter.doFilter(request, response, fc);
		assertThat(response.getRedirectedUrl()).isEqualTo("/mycontext/login.jsp");
		assertThat(getSavedRequestUrl(request)).isEqualTo("https://www.example.com/mycontext/secure/page.html");
	}

	@Test
	public void redirectedToLoginFormAndSessionShowsOriginalTargetWithExoticPortWhenAuthenticationException()
			throws Exception {
		// Setup our HTTP request
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setServletPath("/secure/page.html");
		request.setServerPort(8080);
		request.setScheme("http");
		request.setServerName("www.example.com");
		request.setContextPath("/mycontext");
		request.setRequestURI("/mycontext/secure/page.html");

		// Setup the FilterChain to thrown an authentication failure exception
		FilterChain fc = mock(FilterChain.class);
		doThrow(new BadCredentialsException("")).when(fc).doFilter(
				any(HttpServletRequest.class), any(HttpServletResponse.class));

		// Test
		HttpSessionRequestCache requestCache = new HttpSessionRequestCache();
		ExceptionTranslationFilter filter = new ExceptionTranslationFilter(
				mockEntryPoint, requestCache);
		requestCache.setPortResolver(new MockPortResolver(8080, 8443));
		filter.afterPropertiesSet();
		MockHttpServletResponse response = new MockHttpServletResponse();
		filter.doFilter(request, response, fc);
		assertThat(response.getRedirectedUrl()).isEqualTo("/mycontext/login.jsp");
		assertThat(getSavedRequestUrl(request)).isEqualTo("https://www.example.com:8080/mycontext/secure/page.html");
	}

	@Test(expected = IllegalArgumentException.class)
	public void startupDetectsMissingAuthenticationEntryPoint() throws Exception {
		new ExceptionTranslationFilter(null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void startupDetectsMissingRequestCache() throws Exception {
		new ExceptionTranslationFilter(mockEntryPoint, null);
	}

	@Test
	public void successfulAccessGrant() throws Exception {
		// Setup our HTTP request
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setServletPath("/secure/page.html");

		// Test
		ExceptionTranslationFilter filter = new ExceptionTranslationFilter(mockEntryPoint);
		assertThat(filter.getAuthenticationEntryPoint()).isSameAs(mockEntryPoint);

		MockHttpServletResponse response = new MockHttpServletResponse();
		filter.doFilter(request, response, mock(FilterChain.class));
	}

	@Test
	public void thrownIOExceptionServletExceptionAndRuntimeExceptionsAreRethrown()
			throws Exception {
		ExceptionTranslationFilter filter = new ExceptionTranslationFilter(mockEntryPoint);

		filter.afterPropertiesSet();
		Exception[] exceptions = { new IOException(), new ServletException(),
				new RuntimeException() };
		for (Exception e : exceptions) {
			FilterChain fc = mock(FilterChain.class);

			doThrow(e).when(fc).doFilter(any(HttpServletRequest.class),
					any(HttpServletResponse.class));
			try {
				filter.doFilter(new MockHttpServletRequest(),
						new MockHttpServletResponse(), fc);
				fail("Should have thrown Exception");
			}
			catch (Exception expected) {
				assertThat(expected).isSameAs(e);
			}
		}
	}

	private final AuthenticationEntryPoint mockEntryPoint = new AuthenticationEntryPoint() {
		public void commence(HttpServletRequest request, HttpServletResponse response,
				AuthenticationException authException) throws IOException,
				ServletException {
			response.sendRedirect(request.getContextPath() + "/login.jsp");
		}
	};
}
