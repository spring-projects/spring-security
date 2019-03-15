/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.cas.web;

import static org.junit.Assert.*;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;

import java.lang.reflect.Method;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.jasig.cas.client.proxy.ProxyGrantingTicketStorage;
import org.junit.After;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.NullRememberMeServices;
import org.springframework.util.ReflectionUtils;


/**
 * Tests {@link CasAuthenticationFilter}.
 *
 * @author Ben Alex
 * @author Rob Winch
 */
public class CasAuthenticationFilterTests {
    //~ Methods ========================================================================================================

    @After
    public void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    public void testGettersSetters() {
        CasAuthenticationFilter filter = new CasAuthenticationFilter();
        assertEquals("/j_spring_cas_security_check", filter.getFilterProcessesUrl());
        filter.setProxyGrantingTicketStorage(mock(ProxyGrantingTicketStorage.class));
        filter.setProxyReceptorUrl("/someurl");
        filter.setServiceProperties(new ServiceProperties());
    }

    @Test
    public void testNormalOperation() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/j_spring_cas_security_check");
        request.addParameter("ticket", "ST-0-ER94xMJmn6pha35CQRoZ");

        CasAuthenticationFilter filter = new CasAuthenticationFilter();
        filter.setAuthenticationManager(new AuthenticationManager() {
            public Authentication authenticate(Authentication a) {
                return a;
            }
        });

        assertTrue(filter.requiresAuthentication(request, new MockHttpServletResponse()));

        Authentication result = filter.attemptAuthentication(request, new MockHttpServletResponse());
        assertTrue(result != null);
    }

    @Test(expected=AuthenticationException.class)
    public void testNullServiceTicketHandledGracefully() throws Exception {
        CasAuthenticationFilter filter = new CasAuthenticationFilter();
        filter.setAuthenticationManager(new AuthenticationManager() {
            public Authentication authenticate(Authentication a) {
                throw new BadCredentialsException("Rejected");
            }
        });

        filter.attemptAuthentication(new MockHttpServletRequest(), new MockHttpServletResponse());
    }

    @Test
    public void testRequiresAuthenticationFilterProcessUrl() {
        CasAuthenticationFilter filter = new CasAuthenticationFilter();
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        request.setRequestURI(filter.getFilterProcessesUrl());
        assertTrue(filter.requiresAuthentication(request, response));
    }

    @Test
    public void testRequiresAuthenticationProxyRequest() {
        CasAuthenticationFilter filter = new CasAuthenticationFilter();
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        request.setRequestURI("/pgtCallback");
        assertFalse(filter.requiresAuthentication(request, response));
        filter.setProxyReceptorUrl(request.getRequestURI());
        assertFalse(filter.requiresAuthentication(request, response));
        filter.setProxyGrantingTicketStorage(mock(ProxyGrantingTicketStorage.class));
        assertTrue(filter.requiresAuthentication(request, response));
        request.setRequestURI("/other");
        assertFalse(filter.requiresAuthentication(request, response));
    }

    @Test
    public void testRequiresAuthenticationAuthAll() {
        ServiceProperties properties = new ServiceProperties();
        properties.setAuthenticateAllArtifacts(true);

        CasAuthenticationFilter filter = new CasAuthenticationFilter();
        filter.setServiceProperties(properties);
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        request.setRequestURI(filter.getFilterProcessesUrl());
        assertTrue(filter.requiresAuthentication(request, response));

        request.setRequestURI("/other");
        assertFalse(filter.requiresAuthentication(request, response));
        request.setParameter(properties.getArtifactParameter(), "value");
        assertTrue(filter.requiresAuthentication(request, response));
        SecurityContextHolder.getContext().setAuthentication(new AnonymousAuthenticationToken("key", "principal", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS")));
        assertTrue(filter.requiresAuthentication(request, response));
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("un", "principal", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS")));
        assertTrue(filter.requiresAuthentication(request, response));
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("un", "principal", "ROLE_ANONYMOUS"));
        assertFalse(filter.requiresAuthentication(request, response));
    }

    @Test
    public void testAuthenticateProxyUrl() throws Exception {
        CasAuthenticationFilter filter = new CasAuthenticationFilter();
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        request.setRequestURI("/pgtCallback");
        filter.setProxyGrantingTicketStorage(mock(ProxyGrantingTicketStorage.class));
        filter.setProxyReceptorUrl(request.getRequestURI());
        assertNull(filter.attemptAuthentication(request, response));
    }

    @Test
    public void testDoFilterAuthenticateAll() throws Exception {
        AuthenticationSuccessHandler successHandler = mock(AuthenticationSuccessHandler.class);
        AuthenticationManager manager = mock(AuthenticationManager.class);
        Authentication authentication = new TestingAuthenticationToken("un", "pwd","ROLE_USER");
        when(manager.authenticate(any(Authentication.class))).thenReturn(authentication);
        ServiceProperties serviceProperties = new ServiceProperties();
        serviceProperties.setAuthenticateAllArtifacts(true);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("ticket", "ST-1-123");
        request.setRequestURI("/authenticate");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        CasAuthenticationFilter filter = new CasAuthenticationFilter();
        filter.setServiceProperties(serviceProperties);
        filter.setAuthenticationSuccessHandler(successHandler);
        filter.setProxyGrantingTicketStorage(mock(ProxyGrantingTicketStorage.class));
        filter.setAuthenticationManager(manager);
        filter.afterPropertiesSet();

        filter.doFilter(request,response,chain);
        assertFalse("Authentication should not be null",SecurityContextHolder.getContext().getAuthentication() == null);
        verify(chain).doFilter(request, response);
        verifyZeroInteractions(successHandler);

        // validate for when the filterProcessUrl matches
        filter.setFilterProcessesUrl(request.getRequestURI());
        SecurityContextHolder.clearContext();
        filter.doFilter(request,response,chain);
        verifyNoMoreInteractions(chain);
        verify(successHandler).onAuthenticationSuccess(request, response, authentication);
    }

    // SEC-1592
    @Test
    public void testChainNotInvokedForProxyReceptor() throws Exception {
        CasAuthenticationFilter filter = new CasAuthenticationFilter();
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        request.setRequestURI("/pgtCallback");
        filter.setProxyGrantingTicketStorage(mock(ProxyGrantingTicketStorage.class));
        filter.setProxyReceptorUrl(request.getRequestURI());

        filter.doFilter(request,response,chain);
        verifyZeroInteractions(chain);
    }
}