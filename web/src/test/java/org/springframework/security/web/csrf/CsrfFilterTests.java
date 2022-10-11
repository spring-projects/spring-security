/*
 * Copyright 2002-2022 the original author or authors.
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
import java.util.Base64;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.crypto.codec.Utf8;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.util.matcher.RequestMatcher;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.springframework.security.web.csrf.CsrfTokenAssert.assertThatCsrfToken;

/**
 * @author Rob Winch
 *
 */
@ExtendWith(MockitoExtension.class)
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

	private String csrfAttrName = "_csrf";

	private CsrfFilter filter;

	@BeforeEach
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

	@Test
	public void constructorNullRepository() {
		assertThatIllegalArgumentException().isThrownBy(() -> new CsrfFilter(null));
	}

	// SEC-2276
	@Test
	public void doFilterDoesNotSaveCsrfTokenUntilAccessed() throws ServletException, IOException {
		this.filter = createCsrfFilter(new LazyCsrfTokenRepository(this.tokenRepository));
		given(this.requestMatcher.matches(this.request)).willReturn(false);
		given(this.tokenRepository.generateToken(this.request)).willReturn(this.token);
		this.filter.doFilter(this.request, this.response, this.filterChain);
		CsrfToken attrToken = (CsrfToken) this.request.getAttribute(this.csrfAttrName);
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
		given(this.tokenRepository.loadDeferredToken(this.request, this.response))
				.willReturn(new TestDeferredCsrfToken(this.token, false));
		this.filter.doFilter(this.request, this.response, this.filterChain);
		assertThatCsrfToken(this.request.getAttribute(this.csrfAttrName)).isNotNull();
		assertThatCsrfToken(this.request.getAttribute(CsrfToken.class.getName())).isNotNull();
		verify(this.deniedHandler).handle(eq(this.request), eq(this.response), any(InvalidCsrfTokenException.class));
		verifyNoMoreInteractions(this.filterChain);
	}

	@Test
	public void doFilterAccessDeniedIncorrectTokenPresent() throws ServletException, IOException {
		given(this.requestMatcher.matches(this.request)).willReturn(true);
		given(this.tokenRepository.loadDeferredToken(this.request, this.response))
				.willReturn(new TestDeferredCsrfToken(this.token, false));
		this.request.setParameter(this.token.getParameterName(), this.token.getToken() + " INVALID");
		this.filter.doFilter(this.request, this.response, this.filterChain);
		assertThatCsrfToken(this.request.getAttribute(this.csrfAttrName)).isNotNull();
		assertThatCsrfToken(this.request.getAttribute(CsrfToken.class.getName())).isNotNull();
		verify(this.deniedHandler).handle(eq(this.request), eq(this.response), any(InvalidCsrfTokenException.class));
		verifyNoMoreInteractions(this.filterChain);
	}

	@Test
	public void doFilterAccessDeniedIncorrectTokenPresentHeader() throws ServletException, IOException {
		given(this.requestMatcher.matches(this.request)).willReturn(true);
		given(this.tokenRepository.loadDeferredToken(this.request, this.response))
				.willReturn(new TestDeferredCsrfToken(this.token, false));
		this.request.addHeader(this.token.getHeaderName(), this.token.getToken() + " INVALID");
		this.filter.doFilter(this.request, this.response, this.filterChain);
		assertThatCsrfToken(this.request.getAttribute(this.csrfAttrName)).isNotNull();
		assertThatCsrfToken(this.request.getAttribute(CsrfToken.class.getName())).isNotNull();
		verify(this.deniedHandler).handle(eq(this.request), eq(this.response), any(InvalidCsrfTokenException.class));
		verifyNoMoreInteractions(this.filterChain);
	}

	@Test
	public void doFilterAccessDeniedIncorrectTokenPresentHeaderPreferredOverParameter()
			throws ServletException, IOException {
		given(this.requestMatcher.matches(this.request)).willReturn(true);
		given(this.tokenRepository.loadDeferredToken(this.request, this.response))
				.willReturn(new TestDeferredCsrfToken(this.token, false));
		CsrfTokenRequestHandler handler = new XorCsrfTokenRequestAttributeHandler();
		handler.handle(this.request, this.response, () -> this.token);
		CsrfToken csrfToken = (CsrfToken) this.request.getAttribute(CsrfToken.class.getName());
		this.request.setParameter(csrfToken.getParameterName(), csrfToken.getToken());
		this.request.addHeader(csrfToken.getHeaderName(), csrfToken.getToken() + " INVALID");
		this.filter.doFilter(this.request, this.response, this.filterChain);
		assertThatCsrfToken(this.request.getAttribute(this.csrfAttrName)).isNotNull();
		assertThatCsrfToken(this.request.getAttribute(CsrfToken.class.getName())).isNotNull();
		verify(this.deniedHandler).handle(eq(this.request), eq(this.response), any(InvalidCsrfTokenException.class));
		verifyNoMoreInteractions(this.filterChain);
	}

	@Test
	public void doFilterNotCsrfRequestExistingToken() throws ServletException, IOException {
		given(this.requestMatcher.matches(this.request)).willReturn(false);
		given(this.tokenRepository.loadDeferredToken(this.request, this.response))
				.willReturn(new TestDeferredCsrfToken(this.token, false));
		this.filter.doFilter(this.request, this.response, this.filterChain);
		assertThatCsrfToken(this.request.getAttribute(this.csrfAttrName)).isNotNull();
		assertThatCsrfToken(this.request.getAttribute(CsrfToken.class.getName())).isNotNull();
		verify(this.filterChain).doFilter(this.request, this.response);
		verifyNoMoreInteractions(this.deniedHandler);
	}

	@Test
	public void doFilterNotCsrfRequestGenerateToken() throws ServletException, IOException {
		given(this.requestMatcher.matches(this.request)).willReturn(false);
		given(this.tokenRepository.loadDeferredToken(this.request, this.response))
				.willReturn(new TestDeferredCsrfToken(this.token, true));
		this.filter.doFilter(this.request, this.response, this.filterChain);
		assertThatCsrfToken(this.request.getAttribute(this.csrfAttrName)).isNotNull();
		assertThatCsrfToken(this.request.getAttribute(CsrfToken.class.getName())).isNotNull();
		verify(this.filterChain).doFilter(this.request, this.response);
		verifyNoMoreInteractions(this.deniedHandler);
	}

	@Test
	public void doFilterIsCsrfRequestExistingTokenHeader() throws ServletException, IOException {
		given(this.requestMatcher.matches(this.request)).willReturn(true);
		given(this.tokenRepository.loadDeferredToken(this.request, this.response))
				.willReturn(new TestDeferredCsrfToken(this.token, false));
		CsrfTokenRequestHandler handler = new XorCsrfTokenRequestAttributeHandler();
		handler.handle(this.request, this.response, () -> this.token);
		CsrfToken csrfToken = (CsrfToken) this.request.getAttribute(CsrfToken.class.getName());
		this.request.addHeader(csrfToken.getHeaderName(), csrfToken.getToken());
		this.filter.doFilter(this.request, this.response, this.filterChain);
		assertThatCsrfToken(this.request.getAttribute(this.csrfAttrName)).isNotNull();
		assertThatCsrfToken(this.request.getAttribute(CsrfToken.class.getName())).isNotNull();
		verify(this.filterChain).doFilter(this.request, this.response);
		verifyNoMoreInteractions(this.deniedHandler);
	}

	@Test
	public void doFilterIsCsrfRequestExistingTokenHeaderPreferredOverInvalidParam()
			throws ServletException, IOException {
		given(this.requestMatcher.matches(this.request)).willReturn(true);
		given(this.tokenRepository.loadDeferredToken(this.request, this.response))
				.willReturn(new TestDeferredCsrfToken(this.token, false));
		CsrfTokenRequestHandler handler = new XorCsrfTokenRequestAttributeHandler();
		handler.handle(this.request, this.response, () -> this.token);
		CsrfToken csrfToken = (CsrfToken) this.request.getAttribute(CsrfToken.class.getName());
		this.request.setParameter(csrfToken.getParameterName(), csrfToken.getToken() + " INVALID");
		this.request.addHeader(csrfToken.getHeaderName(), csrfToken.getToken());
		this.filter.doFilter(this.request, this.response, this.filterChain);
		assertThatCsrfToken(this.request.getAttribute(this.csrfAttrName)).isNotNull();
		assertThatCsrfToken(this.request.getAttribute(CsrfToken.class.getName())).isNotNull();
		verify(this.filterChain).doFilter(this.request, this.response);
		verifyNoMoreInteractions(this.deniedHandler);
	}

	@Test
	public void doFilterIsCsrfRequestExistingToken() throws ServletException, IOException {
		given(this.requestMatcher.matches(this.request)).willReturn(true);
		given(this.tokenRepository.loadDeferredToken(this.request, this.response))
				.willReturn(new TestDeferredCsrfToken(this.token, false));
		CsrfTokenRequestHandler handler = new XorCsrfTokenRequestAttributeHandler();
		handler.handle(this.request, this.response, () -> this.token);
		CsrfToken csrfToken = (CsrfToken) this.request.getAttribute(CsrfToken.class.getName());
		this.request.setParameter(csrfToken.getParameterName(), csrfToken.getToken());
		this.filter.doFilter(this.request, this.response, this.filterChain);
		assertThatCsrfToken(this.request.getAttribute(this.csrfAttrName)).isNotNull();
		assertThatCsrfToken(this.request.getAttribute(CsrfToken.class.getName())).isNotNull();
		verify(this.filterChain).doFilter(this.request, this.response);
		verifyNoMoreInteractions(this.deniedHandler);
		verify(this.tokenRepository, never()).saveToken(any(CsrfToken.class), any(HttpServletRequest.class),
				any(HttpServletResponse.class));
	}

	@Test
	public void doFilterIsCsrfRequestGenerateToken() throws ServletException, IOException {
		given(this.requestMatcher.matches(this.request)).willReturn(true);
		given(this.tokenRepository.loadDeferredToken(this.request, this.response))
				.willReturn(new TestDeferredCsrfToken(this.token, true));
		CsrfTokenRequestHandler handler = new XorCsrfTokenRequestAttributeHandler();
		handler.handle(this.request, this.response, () -> this.token);
		CsrfToken csrfToken = (CsrfToken) this.request.getAttribute(CsrfToken.class.getName());
		this.request.setParameter(csrfToken.getParameterName(), csrfToken.getToken());
		this.filter.doFilter(this.request, this.response, this.filterChain);
		assertThatCsrfToken(this.request.getAttribute(this.csrfAttrName)).isNotNull();
		assertThatCsrfToken(this.request.getAttribute(CsrfToken.class.getName())).isNotNull();
		// LazyCsrfTokenRepository requires the response as an attribute
		assertThat(this.request.getAttribute(HttpServletResponse.class.getName())).isEqualTo(this.response);
		verify(this.filterChain).doFilter(this.request, this.response);
		verifyNoMoreInteractions(this.deniedHandler);
	}

	@Test
	public void doFilterDefaultRequireCsrfProtectionMatcherAllowedMethods() throws ServletException, IOException {
		this.filter = new CsrfFilter(this.tokenRepository);
		this.filter.setAccessDeniedHandler(this.deniedHandler);
		for (String method : Arrays.asList("GET", "TRACE", "OPTIONS", "HEAD")) {
			resetRequestResponse();
			given(this.tokenRepository.loadDeferredToken(this.request, this.response))
					.willReturn(new TestDeferredCsrfToken(this.token, false));
			this.request.setMethod(method);
			this.filter.doFilter(this.request, this.response, this.filterChain);
			verify(this.filterChain).doFilter(this.request, this.response);
			verifyNoMoreInteractions(this.deniedHandler);
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
			given(this.tokenRepository.loadDeferredToken(this.request, this.response))
					.willReturn(new TestDeferredCsrfToken(this.token, false));
			this.request.setMethod(method);
			this.filter.doFilter(this.request, this.response, this.filterChain);
			verify(this.deniedHandler).handle(eq(this.request), eq(this.response),
					any(InvalidCsrfTokenException.class));
			verifyNoMoreInteractions(this.filterChain);
		}
	}

	@Test
	public void doFilterDefaultRequireCsrfProtectionMatcherDeniedMethods() throws ServletException, IOException {
		this.filter = new CsrfFilter(this.tokenRepository);
		this.filter.setAccessDeniedHandler(this.deniedHandler);
		for (String method : Arrays.asList("POST", "PUT", "PATCH", "DELETE", "INVALID")) {
			resetRequestResponse();
			given(this.tokenRepository.loadDeferredToken(this.request, this.response))
					.willReturn(new TestDeferredCsrfToken(this.token, false));
			this.request.setMethod(method);
			this.filter.doFilter(this.request, this.response, this.filterChain);
			verify(this.deniedHandler).handle(eq(this.request), eq(this.response),
					any(InvalidCsrfTokenException.class));
			verifyNoMoreInteractions(this.filterChain);
		}
	}

	@Test
	public void doFilterDefaultAccessDenied() throws ServletException, IOException {
		this.filter = new CsrfFilter(this.tokenRepository);
		this.filter.setRequireCsrfProtectionMatcher(this.requestMatcher);
		given(this.requestMatcher.matches(this.request)).willReturn(true);
		given(this.tokenRepository.loadDeferredToken(this.request, this.response))
				.willReturn(new TestDeferredCsrfToken(this.token, false));
		this.filter.doFilter(this.request, this.response, this.filterChain);
		assertThatCsrfToken(this.request.getAttribute(this.csrfAttrName)).isNotNull();
		assertThatCsrfToken(this.request.getAttribute(CsrfToken.class.getName())).isNotNull();
		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_FORBIDDEN);
		verifyNoMoreInteractions(this.filterChain);
	}

	@Test
	public void doFilterWhenSkipRequestInvokedThenSkips() throws Exception {
		CsrfTokenRepository repository = mock(CsrfTokenRepository.class);
		CsrfFilter filter = new CsrfFilter(repository);
		lenient().when(repository.loadToken(any(HttpServletRequest.class))).thenReturn(this.token);
		MockHttpServletRequest request = new MockHttpServletRequest();
		CsrfFilter.skipRequest(request);
		filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());
		verifyNoMoreInteractions(repository);
	}

	// gh-9561
	@Test
	public void doFilterWhenTokenIsNullThenNoNullPointer() throws Exception {
		CsrfFilter filter = createCsrfFilter(this.tokenRepository);
		CsrfToken token = mock(CsrfToken.class);
		given(token.getToken()).willReturn(null);
		given(token.getHeaderName()).willReturn(this.token.getHeaderName());
		given(token.getParameterName()).willReturn(this.token.getParameterName());
		given(this.tokenRepository.loadDeferredToken(this.request, this.response))
				.willReturn(new TestDeferredCsrfToken(token, false));
		given(this.requestMatcher.matches(this.request)).willReturn(true);
		filter.doFilterInternal(this.request, this.response, this.filterChain);
		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
	}

	@Test
	public void doFilterWhenRequestHandlerThenUsed() throws Exception {
		given(this.tokenRepository.loadDeferredToken(this.request, this.response))
				.willReturn(new TestDeferredCsrfToken(this.token, false));
		CsrfTokenRequestHandler requestHandler = mock(CsrfTokenRequestHandler.class);
		this.filter = createCsrfFilter(this.tokenRepository);
		this.filter.setRequestHandler(requestHandler);
		this.request.setParameter(this.token.getParameterName(), this.token.getToken());
		this.filter.doFilter(this.request, this.response, this.filterChain);
		verify(this.tokenRepository).loadDeferredToken(this.request, this.response);
		verify(requestHandler).handle(eq(this.request), eq(this.response), any());
		verify(this.filterChain).doFilter(this.request, this.response);
	}

	@Test
	public void doFilterWhenXorCsrfTokenRequestAttributeHandlerAndValidTokenThenSuccess() throws Exception {
		given(this.requestMatcher.matches(this.request)).willReturn(false);
		given(this.tokenRepository.loadDeferredToken(this.request, this.response))
				.willReturn(new TestDeferredCsrfToken(this.token, false));
		this.filter.doFilter(this.request, this.response, this.filterChain);
		assertThat(this.request.getAttribute(CsrfToken.class.getName())).isNotNull();
		assertThat(this.request.getAttribute("_csrf")).isNotNull();
		verify(this.filterChain).doFilter(this.request, this.response);
		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);

		CsrfToken csrfTokenAttribute = (CsrfToken) this.request.getAttribute(CsrfToken.class.getName());
		byte[] csrfTokenAttributeBytes = Base64.getUrlDecoder().decode(csrfTokenAttribute.getToken());
		byte[] actualTokenBytes = Utf8.encode(this.token.getToken());
		// XOR'd token length is 2x due to containing the random bytes
		assertThat(csrfTokenAttributeBytes).hasSize(actualTokenBytes.length * 2);

		given(this.requestMatcher.matches(this.request)).willReturn(true);
		this.request.setParameter(this.token.getParameterName(), csrfTokenAttribute.getToken());
		this.filter.doFilter(this.request, this.response, this.filterChain);
		verify(this.filterChain, times(2)).doFilter(this.request, this.response);
	}

	@Test
	public void doFilterWhenXorCsrfTokenRequestAttributeHandlerAndRawTokenThenAccessDeniedException() throws Exception {
		given(this.requestMatcher.matches(this.request)).willReturn(true);
		given(this.tokenRepository.loadDeferredToken(this.request, this.response))
				.willReturn(new TestDeferredCsrfToken(this.token, false));
		this.request.setParameter(this.token.getParameterName(), this.token.getToken());
		this.filter.doFilter(this.request, this.response, this.filterChain);
		verify(this.deniedHandler).handle(eq(this.request), eq(this.response), any(AccessDeniedException.class));
		verifyNoMoreInteractions(this.filterChain);
	}

	@Test
	public void setRequireCsrfProtectionMatcherNull() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.filter.setRequireCsrfProtectionMatcher(null));
	}

	@Test
	public void setAccessDeniedHandlerNull() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.filter.setAccessDeniedHandler(null));
	}

	// This ensures that the HttpSession on get requests unless the CsrfToken is used
	@Test
	public void doFilterWhenCsrfRequestAttributeNameThenNoCsrfTokenMethodInvokedOnGet()
			throws ServletException, IOException {
		CsrfFilter filter = createCsrfFilter(this.tokenRepository);
		String csrfAttrName = "_csrf";
		CsrfTokenRequestAttributeHandler requestHandler = new XorCsrfTokenRequestAttributeHandler();
		requestHandler.setCsrfRequestAttributeName(csrfAttrName);
		filter.setRequestHandler(requestHandler);
		CsrfToken expectedCsrfToken = mock(CsrfToken.class);
		given(this.tokenRepository.loadDeferredToken(this.request, this.response))
				.willReturn(new TestDeferredCsrfToken(expectedCsrfToken, true));

		filter.doFilter(this.request, this.response, this.filterChain);

		verifyNoInteractions(expectedCsrfToken);
		CsrfToken tokenFromRequest = (CsrfToken) this.request.getAttribute(csrfAttrName);
		assertThatCsrfToken(tokenFromRequest).isNotNull();
	}

}
