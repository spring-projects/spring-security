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

package org.springframework.security.core.session;

import static org.junit.Assert.*;

import java.util.Date;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.session.SessionDestroyedEvent;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistryImpl;

/**
 * Tests {@link SessionRegistryImpl}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class SessionRegistryImplTests {
    private SessionRegistryImpl sessionRegistry;

    //~ Methods ========================================================================================================

    @Before
    public void setUp() throws Exception {
        sessionRegistry = new SessionRegistryImpl();
    }

    @Test
    public void sessionDestroyedEventRemovesSessionFromRegistry() {
        Object principal = "Some principal object";
        final String sessionId = "zzzz";

        // Register new Session
        sessionRegistry.registerNewSession(sessionId, principal);

        // De-register session via an ApplicationEvent
        sessionRegistry.onApplicationEvent(new SessionDestroyedEvent("") {
            @Override
            public String getId() {
                return sessionId;
            }

            @Override
            public SecurityContext getSecurityContext() {
                return null;
            }
        });

        // Check attempts to retrieve cleared session return null
        assertNull(sessionRegistry.getSessionInformation(sessionId));
    }

    @Test
    public void testMultiplePrincipals() throws Exception {
        Object principal1 = "principal_1";
        Object principal2 = "principal_2";
        String sessionId1 = "1234567890";
        String sessionId2 = "9876543210";
        String sessionId3 = "5432109876";

        sessionRegistry.registerNewSession(sessionId1, principal1);
        sessionRegistry.registerNewSession(sessionId2, principal1);
        sessionRegistry.registerNewSession(sessionId3, principal2);

        assertEquals(2, sessionRegistry.getAllPrincipals().size());
        assertTrue(sessionRegistry.getAllPrincipals().contains(principal1));
        assertTrue(sessionRegistry.getAllPrincipals().contains(principal2));
    }

    @Test
    public void testSessionInformationLifecycle() throws Exception {
        Object principal = "Some principal object";
        String sessionId = "1234567890";
        // Register new Session
        sessionRegistry.registerNewSession(sessionId, principal);

        // Retrieve existing session by session ID
        Date currentDateTime = sessionRegistry.getSessionInformation(sessionId).getLastRequest();
        assertEquals(principal, sessionRegistry.getSessionInformation(sessionId).getPrincipal());
        assertEquals(sessionId, sessionRegistry.getSessionInformation(sessionId).getSessionId());
        assertNotNull(sessionRegistry.getSessionInformation(sessionId).getLastRequest());

        // Retrieve existing session by principal
        assertEquals(1, sessionRegistry.getAllSessions(principal, false).size());

        // Sleep to ensure SessionRegistryImpl will update time
        Thread.sleep(1000);

        // Update request date/time
        sessionRegistry.refreshLastRequest(sessionId);

        Date retrieved = sessionRegistry.getSessionInformation(sessionId).getLastRequest();
        assertTrue(retrieved.after(currentDateTime));

        // Check it retrieves correctly when looked up via principal
        assertEquals(retrieved, sessionRegistry.getAllSessions(principal, false).get(0).getLastRequest());

        // Clear session information
        sessionRegistry.removeSessionInformation(sessionId);

        // Check attempts to retrieve cleared session return null
        assertNull(sessionRegistry.getSessionInformation(sessionId));
        assertNull(sessionRegistry.getAllSessions(principal, false));
    }

    @Test
    public void testTwoSessionsOnePrincipalExpiring() throws Exception {
        Object principal = "Some principal object";
        String sessionId1 = "1234567890";
        String sessionId2 = "9876543210";

        sessionRegistry.registerNewSession(sessionId1, principal);
        List<SessionInformation> sessions = sessionRegistry.getAllSessions(principal, false);
        assertEquals(1, sessions.size());
        assertTrue(contains(sessionId1, principal));

        sessionRegistry.registerNewSession(sessionId2, principal);
        sessions = sessionRegistry.getAllSessions(principal, false);
        assertEquals(2, sessions.size());
        assertTrue(contains(sessionId2, principal));

        // Expire one session
        SessionInformation session = sessionRegistry.getSessionInformation(sessionId2);
        session.expireNow();

        // Check retrieval still correct
        assertTrue(sessionRegistry.getSessionInformation(sessionId2).isExpired());
        assertFalse(sessionRegistry.getSessionInformation(sessionId1).isExpired());
    }

    @Test
    public void testTwoSessionsOnePrincipalHandling() throws Exception {
        Object principal = "Some principal object";
        String sessionId1 = "1234567890";
        String sessionId2 = "9876543210";

        sessionRegistry.registerNewSession(sessionId1, principal);
        List<SessionInformation> sessions = sessionRegistry.getAllSessions(principal, false);
        assertEquals(1, sessions.size());
        assertTrue(contains(sessionId1, principal));

        sessionRegistry.registerNewSession(sessionId2, principal);
        sessions = sessionRegistry.getAllSessions(principal, false);
        assertEquals(2, sessions.size());
        assertTrue(contains(sessionId2, principal));

        sessionRegistry.removeSessionInformation(sessionId1);
        sessions = sessionRegistry.getAllSessions(principal, false);
        assertEquals(1, sessions.size());
        assertTrue(contains(sessionId2, principal));

        sessionRegistry.removeSessionInformation(sessionId2);
        assertNull(sessionRegistry.getSessionInformation(sessionId2));
        assertNull(sessionRegistry.getAllSessions(principal, false));
    }

    private boolean contains(String sessionId, Object principal) {
        List<SessionInformation> info = sessionRegistry.getAllSessions(principal, false);

        for (int i = 0; i < info.size(); i++) {
            if (sessionId.equals(info.get(i).getSessionId())) {
                return true;
            }
        }

        return false;
    }
}
