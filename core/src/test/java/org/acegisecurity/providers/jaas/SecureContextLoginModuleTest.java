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

package net.sf.acegisecurity.providers.jaas;

import junit.framework.TestCase;

import net.sf.acegisecurity.context.ContextHolder;
import net.sf.acegisecurity.context.ContextImpl;
import net.sf.acegisecurity.context.security.SecureContextImpl;
import net.sf.acegisecurity.context.security.SecureContext;
import net.sf.acegisecurity.providers.UsernamePasswordAuthenticationToken;

import java.util.HashSet;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginException;


/**
 * DOCUMENT ME!
 *
 * @author Ray Krueger
 */
public class SecureContextLoginModuleTest extends TestCase {
    //~ Instance fields ========================================================

    private SecureContextLoginModule module = null;
    private Subject subject = new Subject(false, new HashSet(), new HashSet(),
            new HashSet());
    private UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken("principal", "credentials");

    //~ Methods ================================================================

    public void testLoginException() throws Exception {
        try {
            module.login();
            fail("LoginException expected, there is no Authentication in the SecureContext");
        } catch (LoginException e) {
        }
    }

    public void testLoginSuccess() throws Exception {
        SecureContext sc = (SecureContext) ContextHolder.getContext();
        sc.setAuthentication(auth);
        assertTrue("Login should succeed, there is an authentication set", module.login());
        assertTrue("The authentication is not null, this should return true", module.commit());
        assertTrue("Principals should contain the authentication", subject.getPrincipals().contains(auth));
    }

    public void testNoContext() throws Exception {
        ContextHolder.setContext(null);
        assertFalse("Should return false and ask to be ignored", module.login());
    }

    public void testUnsupportedContext() throws Exception {
        ContextHolder.setContext(new ContextImpl());
        assertFalse("Should return false and ask to be ignored", module.login());
    }

    public void testLogout() throws Exception {
        SecureContext sc = (SecureContext) ContextHolder.getContext();
        sc.setAuthentication(auth);
        module.login();
        assertTrue("Should return true as it succeeds", module.logout());
        assertEquals("Authentication should be null", null, module.getAuthentication());

        assertFalse("Principals should not contain the authentication after logout", subject.getPrincipals().contains(auth));
    }

    public void testNullLogout() throws Exception {
        assertFalse(module.logout());
    }

    public void testAbort() throws Exception {
        assertFalse("Should return false, no auth is set", module.abort());
        SecureContext sc = (SecureContext) ContextHolder.getContext();
        sc.setAuthentication(auth);
        module.login();
        module.commit();
        assertTrue(module.abort());
    }

    protected void setUp() throws Exception {
        module = new SecureContextLoginModule();

        module.initialize(subject, null, null, null);

        ContextHolder.setContext(new SecureContextImpl());
    }

    protected void tearDown() throws Exception {
        ContextHolder.setContext(null);
        module = null;
    }
}
