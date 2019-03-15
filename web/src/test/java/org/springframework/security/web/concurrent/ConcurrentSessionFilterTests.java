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

package org.springframework.security.web.concurrent;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import java.util.Date;

import javax.servlet.FilterChain;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.session.ConcurrentSessionFilter;


/**
 * Tests {@link ConcurrentSessionFilter}.
 *
 * @author Ben Alex
 * @author Luke Taylor
 */
public class ConcurrentSessionFilterTests {

    @Test
    public void detectsExpiredSessions() throws Exception {
        // Setup our HTTP request
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        request.setSession(session);

        MockHttpServletResponse response = new MockHttpServletResponse();

        // Setup our test fixture and registry to want this session to be expired
        ConcurrentSessionFilter filter = new ConcurrentSessionFilter();
        filter.setRedirectStrategy(new DefaultRedirectStrategy());
        filter.setLogoutHandlers(new LogoutHandler[] {new SecurityContextLogoutHandler()});

        SessionRegistry registry = new SessionRegistryImpl();
        registry.registerNewSession(session.getId(), "principal");
        registry.getSessionInformation(session.getId()).expireNow();
        filter.setSessionRegistry(registry);
        filter.setExpiredUrl("/expired.jsp");
        filter.afterPropertiesSet();

        FilterChain fc = mock(FilterChain.class);
        filter.doFilter(request, response, fc);
        // Expect that the filter chain will not be invoked, as we redirect to expiredUrl
        verifyZeroInteractions(fc);

        assertEquals("/expired.jsp", response.getRedirectedUrl());
    }

    // As above, but with no expiredUrl set.
    @Test
    public void returnsExpectedMessageWhenNoExpiredUrlSet() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        request.setSession(session);

        MockHttpServletResponse response = new MockHttpServletResponse();

        ConcurrentSessionFilter filter = new ConcurrentSessionFilter();
        SessionRegistry registry = new SessionRegistryImpl();
        registry.registerNewSession(session.getId(), "principal");
        registry.getSessionInformation(session.getId()).expireNow();
        filter.setSessionRegistry(registry);

        FilterChain fc = mock(FilterChain.class);
        filter.doFilter(request, response, fc);
        verifyZeroInteractions(fc);

        assertEquals("This session has been expired (possibly due to multiple concurrent logins being " +
                "attempted as the same user).", response.getContentAsString());
    }

    @Test(expected=IllegalArgumentException.class)
    public void detectsMissingSessionRegistry() throws Exception {
        ConcurrentSessionFilter filter = new ConcurrentSessionFilter();
        filter.afterPropertiesSet();
    }

    @Test(expected=IllegalArgumentException.class)
    public void detectsInvalidUrl() throws Exception {
        ConcurrentSessionFilter filter = new ConcurrentSessionFilter();
        filter.setExpiredUrl("ImNotValid");
        filter.afterPropertiesSet();
    }

    @Test
    public void lastRequestTimeUpdatesCorrectly() throws Exception {
        // Setup our HTTP request
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        request.setSession(session);

        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain fc = mock(FilterChain.class);

        // Setup our test fixture
        ConcurrentSessionFilter filter = new ConcurrentSessionFilter();
        SessionRegistry registry = new SessionRegistryImpl();
        registry.registerNewSession(session.getId(), "principal");

        Date lastRequest = registry.getSessionInformation(session.getId()).getLastRequest();
        filter.setSessionRegistry(registry);
        filter.setExpiredUrl("/expired.jsp");

        Thread.sleep(1000);

        filter.doFilter(request, response, fc);

        verify(fc).doFilter(request, response);
        assertTrue(registry.getSessionInformation(session.getId()).getLastRequest().after(lastRequest));
    }
}
