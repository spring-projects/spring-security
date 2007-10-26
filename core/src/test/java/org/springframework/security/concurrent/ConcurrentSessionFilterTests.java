/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.concurrent;

import junit.framework.TestCase;
import org.springframework.mock.web.MockFilterConfig;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;
import java.util.Date;


/**
 * Tests {@link ConcurrentSessionFilter}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class ConcurrentSessionFilterTests extends TestCase {
    //~ Constructors ===================================================================================================

    public ConcurrentSessionFilterTests(String arg0) {
        super(arg0);
    }

    //~ Methods ========================================================================================================

    private void executeFilterInContainerSimulator(FilterConfig filterConfig, Filter filter, ServletRequest request,
        ServletResponse response, FilterChain filterChain)
        throws ServletException, IOException {
        filter.init(filterConfig);
        filter.doFilter(request, response, filterChain);
        filter.destroy();
    }

    public void testDetectsExpiredSessions() throws Exception {
        // Setup our HTTP request
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        request.setSession(session);

        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterConfig config = new MockFilterConfig(null, null);

        // Setup our expectation that the filter chain will not be invoked, as we redirect to expiredUrl
        MockFilterChain chain = new MockFilterChain(false);

        // Setup our test fixture and registry to want this session to be expired
        ConcurrentSessionFilter filter = new ConcurrentSessionFilter();
        SessionRegistry registry = new SessionRegistryImpl();
        registry.registerNewSession(session.getId(), "principal");
        registry.getSessionInformation(session.getId()).expireNow();
        filter.setSessionRegistry(registry);
        filter.setExpiredUrl("/expired.jsp");

        // Test
        executeFilterInContainerSimulator(config, filter, request, response, chain);

        assertEquals("/expired.jsp", response.getRedirectedUrl());
    }

    // As above, but with no expiredUrl set.
    public void testReturnsExpectedMessageWhenNoExpiredUrlSet() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        request.setSession(session);

        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterConfig config = new MockFilterConfig(null, null);

        MockFilterChain chain = new MockFilterChain(false);

        ConcurrentSessionFilter filter = new ConcurrentSessionFilter();
        SessionRegistry registry = new SessionRegistryImpl();
        registry.registerNewSession(session.getId(), "principal");
        registry.getSessionInformation(session.getId()).expireNow();
        filter.setSessionRegistry(registry);

        executeFilterInContainerSimulator(config, filter, request, response, chain);

        assertEquals("This session has been expired (possibly due to multiple concurrent logins being " +
                "attempted as the same user).", response.getContentAsString());
    }

    public void testDetectsMissingSessionRegistry() throws Exception {
        ConcurrentSessionFilter filter = new ConcurrentSessionFilter();
        filter.setExpiredUrl("xcx");

        try {
            filter.afterPropertiesSet();
            fail("Should have thrown IAE");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testUpdatesLastRequestTime() throws Exception {
        // Setup our HTTP request
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        request.setSession(session);

        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterConfig config = new MockFilterConfig(null, null);

        // Setup our expectation that the filter chain will be invoked, as our session hasn't expired
        MockFilterChain chain = new MockFilterChain(true);

        // Setup our test fixture
        ConcurrentSessionFilter filter = new ConcurrentSessionFilter();
        SessionRegistry registry = new SessionRegistryImpl();
        registry.registerNewSession(session.getId(), "principal");

        Date lastRequest = registry.getSessionInformation(session.getId()).getLastRequest();
        filter.setSessionRegistry(registry);
        filter.setExpiredUrl("/expired.jsp");

        Thread.sleep(1000);

        // Test
        executeFilterInContainerSimulator(config, filter, request, response, chain);

        assertTrue(registry.getSessionInformation(session.getId()).getLastRequest().after(lastRequest));
    }

    //~ Inner Classes ==================================================================================================

    private class MockFilterChain implements FilterChain {
        private boolean expectToProceed;

        public MockFilterChain(boolean expectToProceed) {
            this.expectToProceed = expectToProceed;
        }

        private MockFilterChain() {
            super();
        }

        public void doFilter(ServletRequest request, ServletResponse response)
            throws IOException, ServletException {
            if (expectToProceed) {
                assertTrue(true);
            } else {
                fail("Did not expect filter chain to proceed");
            }
        }
    }
}
