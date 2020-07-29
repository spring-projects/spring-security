/*
 * Copyright 2002-2013 the original author or authors.
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

package org.springframework.security.web.csrf;

import java.io.IOException;
import java.util.Arrays;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.assertj.core.api.AbstractObjectAssert;
import org.assertj.core.api.ObjectAssert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.util.matcher.RequestMatcher;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;

/**
 * @author Rob Winch
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class CsrfFilterTests {

	@Mock
	private RequestMatcher requestMatcher;

	@Mock
	private CsrfTokenRepository tokenRepository;

	@Mock
	private FilterChain filterChain;

	@Mock
	private AccessDeniedHandler deniedHandler;

	private MockHttpServletRequest request;

	private MockHttpServletResponse response;

	private CsrfToken token;

	private CsrfFilter filter;

	@Before
	public void setup() {
		this.token = new DefaultCsrfToken("headerName", "paramName", "csrfTokenValue");
		resetRequestResponse();
		this.filter = createCsrfFilter(this.tokenRepository);
	}

	private CsrfFilter createCsrfFilter(CsrfTokenRepository repository) {
		CsrfFilter filter = new CsrfFilter(repository);
		filter.setRequireCsrfProtectionMatcher(this.requestMatcher);
		filter.setAccessDeniedHandler(this.deniedHandler);
		return filter;
	}

	private void resetRequestResponse() {
		this.request = new MockHttpServletRequest();
		this.response = new MockHttpServletResponse();
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorNullRepository() {
		new CsrfFilter(null);
	}

	// SEC-2276
	@Test
	public void doFilterDoesNotSaveCsrfTokenUntilAccessed() throws ServletException, IOException {
		this.filter = createCsrfFilter(new LazyCsrfTokenRepository(this.tokenRepository));
		given(this.requestMatcher.matches(this.request)).willReturn(false);
		given(this.tokenRepository.generateToken(this.request)).willReturn(this.token);

		this.filter.doFilter(this.request, this.response, this.filterChain);
		CsrfToken attrToken = (CsrfToken) this.request.getAttribute(this.token.getParameterName());

		// no CsrfToken should have been saved yet
		verify(this.tokenRepository, times(0)).saveToken(any(CsrfToken.class), any(HttpServletRequest.class),
				any(HttpServletResponse.class));
		verify(this.filterChain).doFilter(this.request, this.response);

		// access the token
		attrToken.getToken();

		// now the CsrfToken should have been saved
		verify(this.tokenRepository).saveToken(eq(this.token), any(HttpServletRequest.class),
				any(HttpServletResponse.class));
	}

	@Test
	public void doFilterAccessDeniedNoTokenPresent() throws ServletException, IOException {
		given(this.requestMatcher.matches(this.request)).willReturn(true);
		given(this.tokenRepository.loadToken(this.request)).willReturn(this.token);

		this.filter.doFilter(this.request, this.response, this.filterChain);

		assertThat(this.request.getAttribute(this.token.getParameterName())).isEqualTo(this.token);
		assertThat(this.request.getAttribute(CsrfToken.class.getName())).isEqualTo(this.token);

		verify(this.deniedHandler).handle(eq(this.request), eq(this.response), any(InvalidCsrfTokenException.class));
		verifyZeroInteractions(this.filterChain);
	}

	@Test
	public void doFilterAccessDeniedIncorrectTokenPresent() throws ServletException, IOException {
		given(this.requestMatcher.matches(this.request)).willReturn(true);
		given(this.tokenRepository.loadToken(this.request)).willReturn(this.token);
		this.request.setParameter(this.token.getParameterName(), this.token.getToken() + " INVALID");

		this.filter.doFilter(this.request, this.response, this.filterChain);

		assertThat(this.request.getAttribute(this.token.getParameterName())).isEqualTo(this.token);
		assertThat(this.request.getAttribute(CsrfToken.class.getName())).isEqualTo(this.token);

		verify(this.deniedHandler).handle(eq(this.request), eq(this.response), any(InvalidCsrfTokenException.class));
		verifyZeroInteractions(this.filterChain);
	}

	@Test
	public void doFilterAccessDeniedIncorrectTokenPresentHeader() throws ServletException, IOException {
		given(this.requestMatcher.matches(this.request)).willReturn(true);
		given(this.tokenRepository.loadToken(this.request)).willReturn(this.token);
		this.request.addHeader(this.token.getHeaderName(), this.token.getToken() + " INVALID");

		this.filter.doFilter(this.request, this.response, this.filterChain);

		assertThat(this.request.getAttribute(this.token.getParameterName())).isEqualTo(this.token);
		assertThat(this.request.getAttribute(CsrfToken.class.getName())).isEqualTo(this.token);

		verify(this.deniedHandler).handle(eq(this.request), eq(this.response), any(InvalidCsrfTokenException.class));
		verifyZeroInteractions(this.filterChain);
	}

	@Test
	public void doFilterAccessDeniedIncorrectTokenPresentHeaderPreferredOverParameter()
			throws ServletException, IOException {
		given(this.requestMatcher.matches(this.request)).willReturn(true);
		given(this.tokenRepository.loadToken(this.request)).willReturn(this.token);
		this.request.setParameter(this.token.getParameterName(), this.token.getToken());
		this.request.addHeader(this.token.getHeaderName(), this.token.getToken() + " INVALID");

		this.filter.doFilter(this.request, this.response, this.filterChain);

		assertThat(this.request.getAttribute(this.token.getParameterName())).isEqualTo(this.token);
		assertThat(this.request.getAttribute(CsrfToken.class.getName())).isEqualTo(this.token);

		verify(this.deniedHandler).handle(eq(this.request), eq(this.response), any(InvalidCsrfTokenException.class));
		verifyZeroInteractions(this.filterChain);
	}

	@Test
	public void doFilterNotCsrfRequestExistingToken() throws ServletException, IOException {
		given(this.requestMatcher.matches(this.request)).willReturn(false);
		given(this.tokenRepository.loadToken(this.request)).willReturn(this.token);

		this.filter.doFilter(this.request, this.response, this.filterChain);

		assertThat(this.request.getAttribute(this.token.getParameterName())).isEqualTo(this.token);
		assertThat(this.request.getAttribute(CsrfToken.class.getName())).isEqualTo(this.token);

		verify(this.filterChain).doFilter(this.request, this.response);
		verifyZeroInteractions(this.deniedHandler);
	}

	@Test
	public void doFilterNotCsrfRequestGenerateToken() throws ServletException, IOException {
		given(this.requestMatcher.matches(this.request)).willReturn(false);
		given(this.tokenRepository.generateToken(this.request)).willReturn(this.token);

		this.filter.doFilter(this.request, this.response, this.filterChain);

		assertToken(this.request.getAttribute(this.token.getParameterName())).isEqualTo(this.token);
		assertToken(this.request.getAttribute(CsrfToken.class.getName())).isEqualTo(this.token);

		verify(this.filterChain).doFilter(this.request, this.response);
		verifyZeroInteractions(this.deniedHandler);
	}

	@Test
	public void doFilterIsCsrfRequestExistingTokenHeader() throws ServletException, IOException {
		given(this.requestMatcher.matches(this.request)).willReturn(true);
		given(this.tokenRepository.loadToken(this.request)).willReturn(this.token);
		this.request.addHeader(this.token.getHeaderName(), this.token.getToken());

		this.filter.doFilter(this.request, this.response, this.filterChain);

		assertThat(this.request.getAttribute(this.token.getParameterName())).isEqualTo(this.token);
		assertThat(this.request.getAttribute(CsrfToken.class.getName())).isEqualTo(this.token);

		verify(this.filterChain).doFilter(this.request, this.response);
		verifyZeroInteractions(this.deniedHandler);
	}

	@Test
	public void doFilterIsCsrfRequestExistingTokenHeaderPreferredOverInvalidParam()
			throws ServletException, IOException {
		given(this.requestMatcher.matches(this.request)).willReturn(true);
		given(this.tokenRepository.loadToken(this.request)).willReturn(this.token);
		this.request.setParameter(this.token.getParameterName(), this.token.getToken() + " INVALID");
		this.request.addHeader(this.token.getHeaderName(), this.token.getToken());

		this.filter.doFilter(this.request, this.response, this.filterChain);

		assertThat(this.request.getAttribute(this.token.getParameterName())).isEqualTo(this.token);
		assertThat(this.request.getAttribute(CsrfToken.class.getName())).isEqualTo(this.token);

		verify(this.filterChain).doFilter(this.request, this.response);
		verifyZeroInteractions(this.deniedHandler);
	}

	@Test
	public void doFilterIsCsrfRequestExistingToken() throws ServletException, IOException {
		given(this.requestMatcher.matches(this.request)).willReturn(true);
		given(this.tokenRepository.loadToken(this.request)).willReturn(this.token);
		this.request.setParameter(this.token.getParameterName(), this.token.getToken());

		this.filter.doFilter(this.request, this.response, this.filterChain);

		assertThat(this.request.getAttribute(this.token.getParameterName())).isEqualTo(this.token);
		assertThat(this.request.getAttribute(CsrfToken.class.getName())).isEqualTo(this.token);

		verify(this.filterChain).doFilter(this.request, this.response);
		verifyZeroInteractions(this.deniedHandler);
		verify(this.tokenRepository, never()).saveToken(any(CsrfToken.class), any(HttpServletRequest.class),
				any(HttpServletResponse.class));
	}

	@Test
	public void doFilterIsCsrfRequestGenerateToken() throws ServletException, IOException {
		given(this.requestMatcher.matches(this.request)).willReturn(true);
		given(this.tokenRepository.generateToken(this.request)).willReturn(this.token);
		this.request.setParameter(this.token.getParameterName(), this.token.getToken());

		this.filter.doFilter(this.request, this.response, this.filterChain);

		assertToken(this.request.getAttribute(this.token.getParameterName())).isEqualTo(this.token);
		assertToken(this.request.getAttribute(CsrfToken.class.getName())).isEqualTo(this.token);

		// LazyCsrfTokenRepository requires the response as an attribute
		assertThat(this.request.getAttribute(HttpServletResponse.class.getName())).isEqualTo(this.response);

		verify(this.filterChain).doFilter(this.request, this.response);
		verify(this.tokenRepository).saveToken(this.token, this.request, this.response);
		verifyZeroInteractions(this.deniedHandler);
	}

	@Test
	public void doFilterDefaultRequireCsrfProtectionMatcherAllowedMethods() throws ServletException, IOException {
		this.filter = new CsrfFilter(this.tokenRepository);
		this.filter.setAccessDeniedHandler(this.deniedHandler);

		for (String method : Arrays.asList("GET", "TRACE", "OPTIONS", "HEAD")) {
			resetRequestResponse();
			given(this.tokenRepository.loadToken(this.request)).willReturn(this.token);
			this.request.setMethod(method);

			this.filter.doFilter(this.request, this.response, this.filterChain);

			verify(this.filterChain).doFilter(this.request, this.response);
			verifyZeroInteractions(this.deniedHandler);
		}
	}

	/**
	 * SEC-2292 Should not allow other cases through since spec states HTTP method is case
	 * sensitive https://www.w3.org/Protocols/rfc2616/rfc2616-sec5.html#sec5.1.1
	 * @throws Exception if an error occurs
	 *
	 */
	@Test
	public void doFilterDefaultRequireCsrfProtectionMatcherAllowedMethodsCaseSensitive() throws Exception {
		this.filter = new CsrfFilter(this.tokenRepository);
		this.filter.setAccessDeniedHandler(this.deniedHandler);

		for (String method : Arrays.asList("get", "TrAcE", "oPTIOnS", "hEaD")) {
			resetRequestResponse();
			given(this.tokenRepository.loadToken(this.request)).willReturn(this.token);
			this.request.setMethod(method);

			this.filter.doFilter(this.request, this.response, this.filterChain);

			verify(this.deniedHandler).handle(eq(this.request), eq(this.response),
					any(InvalidCsrfTokenException.class));
			verifyZeroInteractions(this.filterChain);
		}
	}

	@Test
	public void doFilterDefaultRequireCsrfProtectionMatcherDeniedMethods() throws ServletException, IOException {
		this.filter = new CsrfFilter(this.tokenRepository);
		this.filter.setAccessDeniedHandler(this.deniedHandler);

		for (String method : Arrays.asList("POST", "PUT", "PATCH", "DELETE", "INVALID")) {
			resetRequestResponse();
			given(this.tokenRepository.loadToken(this.request)).willReturn(this.token);
			this.request.setMethod(method);

			this.filter.doFilter(this.request, this.response, this.filterChain);

			verify(this.deniedHandler).handle(eq(this.request), eq(this.response),
					any(InvalidCsrfTokenException.class));
			verifyZeroInteractions(this.filterChain);
		}
	}

	@Test
	public void doFilterDefaultAccessDenied() throws ServletException, IOException {
		this.filter = new CsrfFilter(this.tokenRepository);
		this.filter.setRequireCsrfProtectionMatcher(this.requestMatcher);
		given(this.requestMatcher.matches(this.request)).willReturn(true);
		given(this.tokenRepository.loadToken(this.request)).willReturn(this.token);

		this.filter.doFilter(this.request, this.response, this.filterChain);

		assertThat(this.request.getAttribute(this.token.getParameterName())).isEqualTo(this.token);
		assertThat(this.request.getAttribute(CsrfToken.class.getName())).isEqualTo(this.token);

		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_FORBIDDEN);
		verifyZeroInteractions(this.filterChain);
	}

	@Test
	public void doFilterWhenSkipRequestInvokedThenSkips() throws Exception {

		CsrfTokenRepository repository = mock(CsrfTokenRepository.class);
		CsrfFilter filter = new CsrfFilter(repository);

		lenient().when(repository.loadToken(any(HttpServletRequest.class))).thenReturn(this.token);

		MockHttpServletRequest request = new MockHttpServletRequest();
		CsrfFilter.skipRequest(request);
		filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

		verifyZeroInteractions(repository);
	}

	@Test(expected = IllegalArgumentException.class)
	public void setRequireCsrfProtectionMatcherNull() {
		this.filter.setRequireCsrfProtectionMatcher(null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void setAccessDeniedHandlerNull() {
		this.filter.setAccessDeniedHandler(null);
	}

	private static CsrfTokenAssert assertToken(Object token) {
		return new CsrfTokenAssert((CsrfToken) token);
	}

	private static class CsrfTokenAssert extends AbstractObjectAssert<CsrfTokenAssert, CsrfToken> {

		/**
		 * Creates a new {@link ObjectAssert}.
		 * @param actual the target to verify.
		 */
		protected CsrfTokenAssert(CsrfToken actual) {
			super(actual, CsrfTokenAssert.class);
		}

		public CsrfTokenAssert isEqualTo(CsrfToken expected) {
			assertThat(this.actual.getHeaderName()).isEqualTo(expected.getHeaderName());
			assertThat(this.actual.getParameterName()).isEqualTo(expected.getParameterName());
			assertThat(this.actual.getToken()).isEqualTo(expected.getToken());
			return this;
		}

	}

}
