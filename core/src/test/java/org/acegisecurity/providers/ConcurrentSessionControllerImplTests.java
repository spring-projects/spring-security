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

package net.sf.acegisecurity.providers;

import junit.framework.TestCase;

import net.sf.acegisecurity.*;
import net.sf.acegisecurity.providers.anonymous.AnonymousAuthenticationToken;
import net.sf.acegisecurity.providers.dao.User;
import net.sf.acegisecurity.ui.WebAuthenticationDetails;
import net.sf.acegisecurity.ui.session.HttpSessionCreatedEvent;
import net.sf.acegisecurity.ui.session.HttpSessionDestroyedEvent;

import org.springframework.context.ApplicationListener;

import java.security.Principal;


/**
 * Tests for {@link ConcurrentSessionControllerImpl}
 *
 * @author Ray Krueger
 */
public class ConcurrentSessionControllerImplTests extends TestCase {
    //~ Instance fields ========================================================

    ConcurrentSessionControllerImpl target;

    //~ Methods ================================================================

    public void testAnonymous() throws Exception {
        AnonymousAuthenticationToken auth = new AnonymousAuthenticationToken("blah",
                "anon",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ANON")});
        target.beforeAuthentication(auth);
        target.afterAuthentication(auth, auth);
    }

    public void testBumpCoverage() throws Exception {
        target.onApplicationEvent(new HttpSessionCreatedEvent(
                new MockHttpSession()));
    }

    public void testEnforcementKnownGood() throws Exception {
        Authentication auth = createAuthentication("user", "password", "session");
        target.beforeAuthentication(auth);
        target.afterAuthentication(auth, auth);
    }

    public void testEnforcementMultipleSessions() throws Exception {
        target.setMaxSessions(5);

        Authentication auth = null;

        for (int i = 0; i < 5; i++) {
            auth = createAuthentication("user", "password", String.valueOf(i));
            target.beforeAuthentication(auth);
            target.afterAuthentication(auth, auth);
        }

        try {
            auth = createAuthentication("user", "password", "lastsession");
            target.beforeAuthentication(auth);
            fail(
                "Only allowed 5 sessions, this should have thrown a ConcurrentLoginException");
        } catch (ConcurrentLoginException e) {
            assertTrue(e.getMessage().startsWith(auth.getPrincipal().toString()));
        }
    }

    public void testEnforcementSingleSession() throws Exception {
        target.setMaxSessions(1);

        Authentication auth = createAuthentication("user", "password",
                "session1");

        target.beforeAuthentication(auth);
        target.afterAuthentication(auth, auth);

        try {
            target.beforeAuthentication(createAuthentication("user",
                    "password", "session2"));
            fail(
                "Only allowed 1 session, this should have thrown a ConcurrentLoginException");
        } catch (ConcurrentLoginException e) {}
    }

    public void testEnforcementUnlimitedSameSession() throws Exception {
        target.setMaxSessions(1);

        for (int i = 0; i < 100; i++) {
            Authentication auth = createAuthentication("user", "password",
                    "samesession");
            target.beforeAuthentication(auth);
            target.afterAuthentication(auth, auth);
        }
    }

    public void testEnforcementUnlimitedSessions() throws Exception {
        target.setMaxSessions(0);

        for (int i = 0; i < 100; i++) {
            Authentication auth = createAuthentication("user", "password",
                    String.valueOf(i));
            target.beforeAuthentication(auth);
            target.afterAuthentication(auth, auth);
        }
    }

    public void testEventHandler() throws Exception {
        target.setMaxSessions(1);

        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken("user",
                "password");
        MockHttpSession session = new MockHttpSession();
        MockHttpServletRequest request = new MockHttpServletRequest(auth,
                session);
        auth.setDetails(new WebAuthenticationDetails(request));

        target.beforeAuthentication(auth);
        target.afterAuthentication(auth, auth);

        target.onApplicationEvent(new HttpSessionDestroyedEvent(session));

        Authentication different = createAuthentication("user", "password",
                "differentsession");
        target.beforeAuthentication(different);
        target.afterAuthentication(different, different);
    }

    public void testEventObject() {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("user",
                "password");
        ConcurrentSessionViolationEvent ev = new ConcurrentSessionViolationEvent(token);
        assertEquals("The token that went in should be the token that comes out",
            token, ev.getAuthentication());
    }

    public void testImplementsApplicationListener() throws Exception {
        assertTrue("This class must implement ApplicationListener, and at one point it didn't.",
            target instanceof ApplicationListener);
    }

    public void testNonWebDetails() throws Exception {
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken("asdf",
                "asdf");
        auth.setDetails("Hi there");
        target.beforeAuthentication(auth);
        target.afterAuthentication(auth, auth);
    }

    public void testPrincipals() throws Exception {
        target.setMaxSessions(1);

        final UserDetails user = new User("user", "password", true, true, true,
                true, new GrantedAuthority[0]);
        final UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(user,
                "password", user.getAuthorities());
        auth.setDetails(createWebDetails(auth, "session1"));

        target.beforeAuthentication(auth);
        target.afterAuthentication(auth, auth);

        try {
            UsernamePasswordAuthenticationToken otherAuth = new UsernamePasswordAuthenticationToken(new Principal() {
                        public String getName() {
                            return "user";
                        }

                        public String toString() {
                            return getName();
                        }
                    }, "password");

            otherAuth.setDetails(createWebDetails(otherAuth, "session2"));
            target.beforeAuthentication(otherAuth);
            fail(
                "Same principal, different principal type, different session should have thrown ConcurrentLoginException");
        } catch (ConcurrentLoginException e) {}
    }

    public void testSetMax() throws Exception {
        target.setMaxSessions(1);
        assertEquals(1, target.getMaxSessions());

        target.setMaxSessions(2);
        assertEquals(2, target.getMaxSessions());
    }

    public void testSetTrustManager() throws Exception {
        assertNotNull("There is supposed to be a default AuthenticationTrustResolver",
            target.getTrustResolver());

        AuthenticationTrustResolverImpl impl = new AuthenticationTrustResolverImpl();
        target.setTrustResolver(impl);
        assertEquals(impl, target.getTrustResolver());
    }

    public void testUtilityMethods() throws Exception {
        Object key = new Object();

        target.addSession(key, "1");
        target.addSession(key, "2");
        target.addSession(key, "3");

        target.removeSession("2");

        assertFalse(target.isActiveSession(key, "2"));
        assertTrue(target.isActiveSession(key, "1"));
        assertTrue(target.isActiveSession(key, "3"));

        assertNull(target.sessionsToPrincipals.get("2"));

        assertEquals(2, target.countSessions(key));
        target.addSession(key, "2");
        assertEquals(3, target.countSessions(key));

        target.addSession(key, "2");
        target.addSession(key, "2");
        assertEquals(3, target.countSessions(key));

        assertTrue(target.isActiveSession(key, "1"));
        assertTrue(target.isActiveSession(key, "2"));
        assertTrue(target.isActiveSession(key, "3"));

        assertFalse(target.isActiveSession(key, "nope"));

        assertFalse(target.isActiveSession(new Object(), "1"));
        assertFalse(target.isActiveSession(new Object(), "1"));

        target.removeSession("nothing to see here");
    }

    protected void setUp() throws Exception {
        target = new ConcurrentSessionControllerImpl();
        target.setApplicationContext(MockApplicationContext.getContext());
    }

    private Authentication createAuthentication(String user, String password,
        String sessionId) {
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(user,
                password);
        auth.setDetails(createWebDetails(auth, sessionId));

        return auth;
    }

    private WebAuthenticationDetails createWebDetails(Authentication auth,
        String sessionId) {
        MockHttpSession session = new MockHttpSession(sessionId);
        MockHttpServletRequest request = new MockHttpServletRequest(auth,
                session);

        return new WebAuthenticationDetails(request);
    }
}
