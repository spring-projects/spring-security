/* Copyright 2004, 2005 Acegi Technology Pty Limited
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

package org.acegisecurity.concurrent;

import junit.framework.TestCase;

import org.acegisecurity.Authentication;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.ui.WebAuthenticationDetails;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;


/**
 * Tests {@link ConcurrentSessionControllerImpl}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class ConcurrentSessionControllerImplTests extends TestCase {
    //~ Methods ================================================================

    public void testLifecycle() throws Exception {
        // Build a test fixture
        ConcurrentSessionControllerImpl sc = new ConcurrentSessionControllerImpl();
        SessionRegistry registry = new SessionRegistryImpl();
        sc.setSessionRegistry(registry);

        // Attempt to authenticate - it should be successful
        Authentication auth = createAuthentication("bob", "1212");
        sc.checkAuthenticationAllowed(auth);
        sc.registerSuccessfulAuthentication(auth);

        String sessionId1 = ((WebAuthenticationDetails) auth.getDetails())
            .getSessionId();
        assertFalse(registry.getSessionInformation(sessionId1).isExpired());

        // Attempt to authenticate again - it should still be successful
        sc.checkAuthenticationAllowed(auth);
        sc.registerSuccessfulAuthentication(auth);

        // Attempt to authenticate with a different session for same principal - should fail
        sc.setExceptionIfMaximumExceeded(true);

        Authentication auth2 = createAuthentication("bob", "1212");
        assertFalse(registry.getSessionInformation(sessionId1).isExpired());

        try {
            sc.checkAuthenticationAllowed(auth2);
            fail("Should have thrown ConcurrentLoginException");
        } catch (ConcurrentLoginException expected) {
            assertTrue(true);
        }

        // Attempt to authenticate with a different session for same principal - should expire first session
        sc.setExceptionIfMaximumExceeded(false);

        Authentication auth3 = createAuthentication("bob", "1212");
        sc.checkAuthenticationAllowed(auth3);
        sc.registerSuccessfulAuthentication(auth3);

        String sessionId3 = ((WebAuthenticationDetails) auth3.getDetails())
            .getSessionId();
        assertTrue(registry.getSessionInformation(sessionId1).isExpired());
        assertFalse(registry.getSessionInformation(sessionId3).isExpired());
    }

    public void testStartupDetectsInvalidMaximumSessions()
        throws Exception {
        ConcurrentSessionControllerImpl sc = new ConcurrentSessionControllerImpl();
        sc.setMaximumSessions(0);

        try {
            sc.afterPropertiesSet();
            fail("Should have thrown IAE");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testStartupDetectsInvalidSessionRegistry()
        throws Exception {
        ConcurrentSessionControllerImpl sc = new ConcurrentSessionControllerImpl();
        sc.setSessionRegistry(null);

        try {
            sc.afterPropertiesSet();
            fail("Should have thrown IAE");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    private Authentication createAuthentication(String user, String password) {
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(user,
                password);
        auth.setDetails(createWebDetails(auth));

        return auth;
    }

    private WebAuthenticationDetails createWebDetails(Authentication auth) {
        MockHttpSession session = new MockHttpSession();
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setSession(session);
        request.setUserPrincipal(auth);

        return new WebAuthenticationDetails(request);
    }
}
