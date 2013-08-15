/*
 * Copyright 2002-2013 the original author or authors.
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
package org.springframework.security.web.csrf;

import static org.fest.assertions.Assertions.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.util.Arrays;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.util.RequestMatcher;

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
        token = new CsrfToken("headerName","paramName", "csrfTokenValue");
        resetRequestResponse();
        filter = new CsrfFilter(tokenRepository);
        filter.setRequireCsrfProtectionMatcher(requestMatcher);
        filter.setAccessDeniedHandler(deniedHandler);
    }

    private void resetRequestResponse() {
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
    }

    @Test(expected = IllegalArgumentException.class)
    public void constructorNullRepository() {
        new CsrfFilter(null);
    }

    @Test
    public void doFilterAccessDeniedNoTokenPresent() throws ServletException, IOException {
        when(requestMatcher.matches(request)).thenReturn(true);
        when(tokenRepository.loadToken(request)).thenReturn(token);

        filter.doFilter(request, response, filterChain);

        assertThat(response.getHeader(token.getHeaderName())).isEqualTo(token.getToken());
        assertThat(request.getAttribute(token.getParameterName())).isEqualTo(token);
        assertThat(request.getAttribute(CsrfToken.class.getName())).isEqualTo(token);

        verify(deniedHandler).handle(eq(request), eq(response), any(InvalidCsrfTokenException.class));
        verifyZeroInteractions(filterChain);
    }

    @Test
    public void doFilterAccessDeniedIncorrectTokenPresent() throws ServletException, IOException {
        when(requestMatcher.matches(request)).thenReturn(true);
        when(tokenRepository.loadToken(request)).thenReturn(token);
        request.setParameter(token.getParameterName(), token.getToken()+ " INVALID");

        filter.doFilter(request, response, filterChain);

        assertThat(response.getHeader(token.getHeaderName())).isEqualTo(token.getToken());
        assertThat(request.getAttribute(token.getParameterName())).isEqualTo(token);
        assertThat(request.getAttribute(CsrfToken.class.getName())).isEqualTo(token);

        verify(deniedHandler).handle(eq(request), eq(response), any(InvalidCsrfTokenException.class));
        verifyZeroInteractions(filterChain);
    }

    @Test
    public void doFilterAccessDeniedIncorrectTokenPresentHeader() throws ServletException, IOException {
        when(requestMatcher.matches(request)).thenReturn(true);
        when(tokenRepository.loadToken(request)).thenReturn(token);
        request.addHeader(token.getHeaderName(), token.getToken()+ " INVALID");

        filter.doFilter(request, response, filterChain);

        assertThat(response.getHeader(token.getHeaderName())).isEqualTo(token.getToken());
        assertThat(request.getAttribute(token.getParameterName())).isEqualTo(token);
        assertThat(request.getAttribute(CsrfToken.class.getName())).isEqualTo(token);

        verify(deniedHandler).handle(eq(request), eq(response), any(InvalidCsrfTokenException.class));
        verifyZeroInteractions(filterChain);
    }

    @Test
    public void doFilterAccessDeniedIncorrectTokenPresentHeaderPreferredOverParameter() throws ServletException, IOException {
        when(requestMatcher.matches(request)).thenReturn(true);
        when(tokenRepository.loadToken(request)).thenReturn(token);
        request.setParameter(token.getParameterName(), token.getToken());
        request.addHeader(token.getHeaderName(), token.getToken()+ " INVALID");

        filter.doFilter(request, response, filterChain);

        assertThat(response.getHeader(token.getHeaderName())).isEqualTo(token.getToken());
        assertThat(request.getAttribute(token.getParameterName())).isEqualTo(token);
        assertThat(request.getAttribute(CsrfToken.class.getName())).isEqualTo(token);

        verify(deniedHandler).handle(eq(request), eq(response), any(InvalidCsrfTokenException.class));
        verifyZeroInteractions(filterChain);
    }

    @Test
    public void doFilterNotCsrfRequestExistingToken() throws ServletException, IOException {
        when(requestMatcher.matches(request)).thenReturn(false);
        when(tokenRepository.loadToken(request)).thenReturn(token);

        filter.doFilter(request, response, filterChain);

        assertThat(response.getHeader(token.getHeaderName())).isEqualTo(token.getToken());
        assertThat(request.getAttribute(token.getParameterName())).isEqualTo(token);
        assertThat(request.getAttribute(CsrfToken.class.getName())).isEqualTo(token);

        verify(filterChain).doFilter(request, response);
        verifyZeroInteractions(deniedHandler);
    }

    @Test
    public void doFilterNotCsrfRequestGenerateToken() throws ServletException, IOException {
        when(requestMatcher.matches(request)).thenReturn(false);
        when(tokenRepository.generateAndSaveToken(request, response)).thenReturn(token);

        filter.doFilter(request, response, filterChain);

        assertThat(response.getHeader(token.getHeaderName())).isEqualTo(token.getToken());
        assertThat(request.getAttribute(token.getParameterName())).isEqualTo(token);
        assertThat(request.getAttribute(CsrfToken.class.getName())).isEqualTo(token);

        verify(filterChain).doFilter(request, response);
        verifyZeroInteractions(deniedHandler);
    }

    @Test
    public void doFilterIsCsrfRequestExistingTokenHeader() throws ServletException, IOException {
        when(requestMatcher.matches(request)).thenReturn(true);
        when(tokenRepository.loadToken(request)).thenReturn(token);
        request.addHeader(token.getHeaderName(), token.getToken());

        filter.doFilter(request, response, filterChain);

        assertThat(response.getHeader(token.getHeaderName())).isEqualTo(token.getToken());
        assertThat(request.getAttribute(token.getParameterName())).isEqualTo(token);
        assertThat(request.getAttribute(CsrfToken.class.getName())).isEqualTo(token);

        verify(filterChain).doFilter(request, response);
        verifyZeroInteractions(deniedHandler);
    }

    @Test
    public void doFilterIsCsrfRequestExistingTokenHeaderPreferredOverInvalidParam() throws ServletException, IOException {
        when(requestMatcher.matches(request)).thenReturn(true);
        when(tokenRepository.loadToken(request)).thenReturn(token);
        request.setParameter(token.getParameterName(), token.getToken()+ " INVALID");
        request.addHeader(token.getHeaderName(), token.getToken());

        filter.doFilter(request, response, filterChain);

        assertThat(response.getHeader(token.getHeaderName())).isEqualTo(token.getToken());
        assertThat(request.getAttribute(token.getParameterName())).isEqualTo(token);
        assertThat(request.getAttribute(CsrfToken.class.getName())).isEqualTo(token);

        verify(filterChain).doFilter(request, response);
        verifyZeroInteractions(deniedHandler);
    }

    @Test
    public void doFilterIsCsrfRequestExistingToken() throws ServletException, IOException {
        when(requestMatcher.matches(request)).thenReturn(true);
        when(tokenRepository.loadToken(request)).thenReturn(token);
        request.setParameter(token.getParameterName(), token.getToken());

        filter.doFilter(request, response, filterChain);

        assertThat(response.getHeader(token.getHeaderName())).isEqualTo(token.getToken());
        assertThat(request.getAttribute(token.getParameterName())).isEqualTo(token);
        assertThat(request.getAttribute(CsrfToken.class.getName())).isEqualTo(token);

        verify(filterChain).doFilter(request, response);
        verifyZeroInteractions(deniedHandler);
    }

    @Test
    public void doFilterIsCsrfRequestGenerateToken() throws ServletException, IOException {
        when(requestMatcher.matches(request)).thenReturn(true);
        when(tokenRepository.generateAndSaveToken(request, response)).thenReturn(token);
        request.setParameter(token.getParameterName(), token.getToken());

        filter.doFilter(request, response, filterChain);

        assertThat(response.getHeader(token.getHeaderName())).isEqualTo(token.getToken());
        assertThat(request.getAttribute(token.getParameterName())).isEqualTo(token);
        assertThat(request.getAttribute(CsrfToken.class.getName())).isEqualTo(token);

        verify(filterChain).doFilter(request, response);
        verifyZeroInteractions(deniedHandler);
    }

    @Test
    public void doFilterDefaultRequireCsrfProtectionMatcherAllowedMethods() throws ServletException, IOException {
        filter = new CsrfFilter(tokenRepository);
        filter.setAccessDeniedHandler(deniedHandler);

        for(String method : Arrays.asList("GET","TRACE", "OPTIONS", "HEAD")) {
            resetRequestResponse();
            when(tokenRepository.loadToken(request)).thenReturn(token);
            request.setMethod(method);

            filter.doFilter(request, response, filterChain);

            verify(filterChain).doFilter(request, response);
            verifyZeroInteractions(deniedHandler);
        }
    }

    @Test
    public void doFilterDefaultRequireCsrfProtectionMatcherDeniedMethods() throws ServletException, IOException {
        filter = new CsrfFilter(tokenRepository);
        filter.setAccessDeniedHandler(deniedHandler);

        for(String method : Arrays.asList("POST","PUT", "PATCH", "DELETE", "INVALID")) {
            resetRequestResponse();
            when(tokenRepository.loadToken(request)).thenReturn(token);
            request.setMethod(method);

            filter.doFilter(request, response, filterChain);

            verify(deniedHandler).handle(eq(request), eq(response), any(InvalidCsrfTokenException.class));
            verifyZeroInteractions(filterChain);
        }
    }

    @Test
    public void doFilterDefaultAccessDenied() throws ServletException, IOException {
        filter = new CsrfFilter(tokenRepository);
        filter.setRequireCsrfProtectionMatcher(requestMatcher);
        when(requestMatcher.matches(request)).thenReturn(true);
        when(tokenRepository.loadToken(request)).thenReturn(token);

        filter.doFilter(request, response, filterChain);

        assertThat(response.getHeader(token.getHeaderName())).isEqualTo(token.getToken());
        assertThat(request.getAttribute(token.getParameterName())).isEqualTo(token);
        assertThat(request.getAttribute(CsrfToken.class.getName())).isEqualTo(token);

        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_FORBIDDEN);
        verifyZeroInteractions(filterChain);
    }

    @Test(expected = IllegalArgumentException.class)
    public void setRequireCsrfProtectionMatcherNull() {
        filter.setRequireCsrfProtectionMatcher(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void setAccessDeniedHandlerNull() {
        filter.setAccessDeniedHandler(null);
    }
}
