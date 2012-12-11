/* Copyright 2002-2012 the original author or authors.
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.web.servletapi;

import static org.fest.assertions.Assertions.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.powermock.api.mockito.PowerMockito.doThrow;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.verifyZeroInteractions;
import static org.powermock.api.mockito.PowerMockito.when;

import java.util.Arrays;
import java.util.List;

import javax.servlet.AsyncContext;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import junit.framework.Assert;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.powermock.reflect.internal.WhiteboxImpl;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.concurrent.DelegatingSecurityContextRunnable;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.util.ClassUtils;


/**
 * Tests {@link SecurityContextHolderAwareRequestFilter}.
 *
 * @author Ben Alex
 * @author Rob Winch
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest(ClassUtils.class)
public class SecurityContextHolderAwareRequestFilterTests {
    @Captor
    private ArgumentCaptor<HttpServletRequest> requestCaptor;
    @Mock
    private AuthenticationManager authenticationManager;
    @Mock
    private AuthenticationEntryPoint authenticationEntryPoint;
    @Mock
    private LogoutHandler logoutHandler;
    @Mock
    private FilterChain filterChain;
    @Mock
    private HttpServletRequest request;
    @Mock
    private HttpServletResponse response;

    private List<LogoutHandler> logoutHandlers;

    private SecurityContextHolderAwareRequestFilter filter;

    @Before
    public void setUp() throws Exception {
        logoutHandlers = Arrays.asList(logoutHandler);
        filter = new SecurityContextHolderAwareRequestFilter();
        filter.setAuthenticationEntryPoint(authenticationEntryPoint);
        filter.setAuthenticationManager(authenticationManager);
        filter.setLogoutHandlers(logoutHandlers);
        filter.afterPropertiesSet();
    }

    @After
    public void clearContext() {
        SecurityContextHolder.clearContext();
    }

    //~ Methods ========================================================================================================

    @Test
    public void expectedRequestWrapperClassIsUsed() throws Exception {
        filter.setRolePrefix("ROLE_");

        filter.doFilter(new MockHttpServletRequest(), new MockHttpServletResponse(), filterChain);

        // Now re-execute the filter, ensuring our replacement wrapper is still used
        filter.doFilter(new MockHttpServletRequest(), new MockHttpServletResponse(), filterChain);

        verify(filterChain, times(2)).doFilter(any(SecurityContextHolderAwareRequestWrapper.class), any(HttpServletResponse.class));

        filter.destroy();
    }

    @Test
    public void authenticateFalse() throws Exception {
        assertThat(wrappedRequest().authenticate(response)).isFalse();
        verify(authenticationEntryPoint).commence(eq(requestCaptor.getValue()), eq(response), any(AuthenticationException.class));
        verifyZeroInteractions(authenticationManager, logoutHandler);
        verify(request, times(0)).authenticate(any(HttpServletResponse.class));
    }

    @Test
    public void authenticateTrue() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("test","password","ROLE_USER"));

        assertThat(wrappedRequest().authenticate(response)).isTrue();
        verifyZeroInteractions(authenticationEntryPoint, authenticationManager, logoutHandler);
        verify(request, times(0)).authenticate(any(HttpServletResponse.class));
    }

    @Test
    public void authenticateNullEntryPointFalse() throws Exception {
        filter.setAuthenticationEntryPoint(null);
        filter.afterPropertiesSet();

        assertThat(wrappedRequest().authenticate(response)).isFalse();
        verify(request).authenticate(response);
        verifyZeroInteractions(authenticationEntryPoint, authenticationManager, logoutHandler);
    }

    @Test
    public void authenticateNullEntryPointTrue() throws Exception {
        when(request.authenticate(response)).thenReturn(true);
        filter.setAuthenticationEntryPoint(null);
        filter.afterPropertiesSet();

        assertThat(wrappedRequest().authenticate(response)).isTrue();
        verify(request).authenticate(response);
        verifyZeroInteractions(authenticationEntryPoint, authenticationManager, logoutHandler);
    }

    @Test
    public void login() throws Exception {
        TestingAuthenticationToken expectedAuth = new TestingAuthenticationToken("user", "password","ROLE_USER");
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class))).thenReturn(expectedAuth);

        wrappedRequest().login(expectedAuth.getName(),String.valueOf(expectedAuth.getCredentials()));

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(expectedAuth);
        verifyZeroInteractions(authenticationEntryPoint, logoutHandler);
        verify(request, times(0)).login(anyString(),anyString());
    }

    @Test
    public void loginFail() throws Exception {
        AuthenticationException authException = new BadCredentialsException("Invalid");
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class))).thenThrow(authException);
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("should","be cleared","ROLE_USER"));

        try {
            wrappedRequest().login("invalid","credentials");
            Assert.fail("Expected Exception");
        } catch(ServletException success) {
            assertThat(success.getCause()).isEqualTo(authException);
        }
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();

        verifyZeroInteractions(authenticationEntryPoint, logoutHandler);
        verify(request, times(0)).login(anyString(),anyString());
    }

    @Test
    public void loginNullAuthenticationManager() throws Exception {
        filter.setAuthenticationManager(null);
        filter.afterPropertiesSet();

        String username = "username";
        String password = "password";

        wrappedRequest().login(username, password);

        verify(request).login(username, password);
        verifyZeroInteractions(authenticationEntryPoint, authenticationManager, logoutHandler);
    }

    @Test
    public void loginNullAuthenticationManagerFail() throws Exception {
        filter.setAuthenticationManager(null);
        filter.afterPropertiesSet();

        String username = "username";
        String password = "password";
        ServletException authException = new ServletException("Failed Login");
        doThrow(authException).when(request).login(username, password);

        try {
            wrappedRequest().login(username, password);
            Assert.fail("Expected Exception");
        } catch(ServletException success) {
            assertThat(success).isEqualTo(authException);
        }

        verifyZeroInteractions(authenticationEntryPoint, authenticationManager, logoutHandler);
    }

    @Test
    public void logout() throws Exception {
        TestingAuthenticationToken expectedAuth = new TestingAuthenticationToken("user", "password","ROLE_USER");
        SecurityContextHolder.getContext().setAuthentication(expectedAuth);

        HttpServletRequest wrappedRequest = wrappedRequest();
        wrappedRequest.logout();

        verify(logoutHandler).logout(wrappedRequest, response, expectedAuth);
        verifyZeroInteractions(authenticationManager, logoutHandler);
        verify(request, times(0)).logout();
    }

    @Test
    public void logoutNullLogoutHandler() throws Exception {
        filter.setLogoutHandlers(null);
        filter.afterPropertiesSet();

        wrappedRequest().logout();

        verify(request).logout();
        verifyZeroInteractions(authenticationEntryPoint, authenticationManager, logoutHandler);
    }

    private HttpServletRequest wrappedRequest() throws Exception {
        filter.doFilter(request, response, filterChain);
        verify(filterChain).doFilter(requestCaptor.capture(), any(HttpServletResponse.class));

        return requestCaptor.getValue();
    }
}
