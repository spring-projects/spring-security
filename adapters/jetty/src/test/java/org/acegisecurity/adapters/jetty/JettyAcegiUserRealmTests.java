/* Copyright 2004 Acegi Technology Pty Limited
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

package net.sf.acegisecurity.adapters.jetty;

import junit.framework.TestCase;

import org.mortbay.http.UserPrincipal;


/**
 * Tests {@link JettyAcegiUserRealm}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class JettyAcegiUserRealmTests extends TestCase {
    //~ Instance fields ========================================================

    private final String ADAPTER_KEY = "my_key";
    private final String REALM_NAME = "Acegi Powered Realm";

    //~ Constructors ===========================================================

    public JettyAcegiUserRealmTests() {
        super();
    }

    public JettyAcegiUserRealmTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(JettyAcegiUserRealmTests.class);
    }

    public void testAdapterAbortsIfAppContextDoesNotContainAnAuthenticationBean()
        throws Exception {
        try {
            JettyAcegiUserRealm adapter = makeAdapter("adaptertest-invalid.xml");
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("Bean context must contain at least one bean of type AuthenticationManager",
                expected.getMessage());
        }
    }

    public void testAdapterAbortsIfNoAppContextSpecified()
        throws Exception {
        try {
            new JettyAcegiUserRealm(REALM_NAME, ADAPTER_KEY, null);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("appContextLocation must be specified",
                expected.getMessage());
        }

        try {
            new JettyAcegiUserRealm(REALM_NAME, ADAPTER_KEY, "");
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("appContextLocation must be specified",
                expected.getMessage());
        }
    }

    public void testAdapterAbortsIfNoKeySpecified() throws Exception {
        try {
            new JettyAcegiUserRealm(REALM_NAME, null, "SOME_PATH");
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("key must be specified", expected.getMessage());
        }

        try {
            new JettyAcegiUserRealm(REALM_NAME, "", "SOME_PATH");
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("key must be specified", expected.getMessage());
        }
    }

    public void testAdapterAbortsIfNoRealmNameSpecified()
        throws Exception {
        try {
            new JettyAcegiUserRealm(null, ADAPTER_KEY, "SOME_PATH");
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("realm must be specified", expected.getMessage());
        }

        try {
            new JettyAcegiUserRealm(null, ADAPTER_KEY, "SOME_PATH");
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("realm must be specified", expected.getMessage());
        }
    }

    public void testAdapterAbortsWithIncorrectApplicationContextLocation()
        throws Exception {
        try {
            new JettyAcegiUserRealm(REALM_NAME, ADAPTER_KEY,
                "SOME_INVALID_LOCATION");
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().startsWith("Cannot locate"));
        }
    }

    public void testAdapterIdentifiesTheRealmItManages()
        throws Exception {
        JettyAcegiUserRealm adapter = makeAdapter("adaptertest-valid.xml");
        assertEquals(REALM_NAME, adapter.getName());
    }

    public void testAdapterStartsUpSuccess() throws Exception {
        JettyAcegiUserRealm adapter = makeAdapter("adaptertest-valid.xml");
        assertTrue(true);
    }

    public void testAuthenticationFailsForIncorrectPassword()
        throws Exception {
        JettyAcegiUserRealm adapter = makeAdapter("adaptertest-valid.xml");
        assertEquals(null, adapter.authenticate("marissa", "kangaroo", null));
    }

    public void testAuthenticationFailsForIncorrectUserName()
        throws Exception {
        JettyAcegiUserRealm adapter = makeAdapter("adaptertest-valid.xml");
        assertEquals(null, adapter.authenticate("melissa", "koala", null));
    }

    public void testAuthenticationSuccess() throws Exception {
        JettyAcegiUserRealm adapter = makeAdapter("adaptertest-valid.xml");
        UserPrincipal result = adapter.authenticate("marissa", "koala", null);

        if (!(result instanceof JettyAcegiUserToken)) {
            fail("Should have returned JettyAcegiUserToken");
        }

        JettyAcegiUserToken castResult = (JettyAcegiUserToken) result;
        assertEquals("marissa", castResult.getPrincipal());
        assertEquals("koala", castResult.getCredentials());
        assertEquals("ROLE_TELLER",
            castResult.getAuthorities()[0].getAuthority());
        assertEquals("ROLE_SUPERVISOR",
            castResult.getAuthorities()[1].getAuthority());
        assertEquals(ADAPTER_KEY.hashCode(), castResult.getKeyHash());
    }

    public void testAuthenticationWithNullPasswordHandledGracefully()
        throws Exception {
        JettyAcegiUserRealm adapter = makeAdapter("adaptertest-valid.xml");
        assertEquals(null, adapter.authenticate("marissa", null, null));
    }

    public void testAuthenticationWithNullUserNameHandledGracefully()
        throws Exception {
        JettyAcegiUserRealm adapter = makeAdapter("adaptertest-valid.xml");
        assertEquals(null, adapter.authenticate(null, "koala", null));
    }

    public void testDisassociateImplemented() throws Exception {
        JettyAcegiUserRealm adapter = makeAdapter("adaptertest-valid.xml");
        adapter.disassociate(new MockUserPrincipal());
        assertTrue(true);
    }

    public void testGetAuthenticationManager() throws Exception {
        JettyAcegiUserRealm adapter = makeAdapter("adaptertest-valid.xml");
        assertTrue(adapter.getAuthenticationManager() != null);
    }

    public void testLogoutImplemented() throws Exception {
        JettyAcegiUserRealm adapter = makeAdapter("adaptertest-valid.xml");
        adapter.logout(new MockUserPrincipal());
        assertTrue(true);
    }

    public void testNoArgsConstructor() {
        try {
            new JettyAcegiUserRealm();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testPopRoleImplemented() throws Exception {
        JettyAcegiUserRealm adapter = makeAdapter("adaptertest-valid.xml");
        MockUserPrincipal user = new MockUserPrincipal();
        assertEquals(user, adapter.popRole(user));
    }

    public void testPushRoleImplemented() throws Exception {
        JettyAcegiUserRealm adapter = makeAdapter("adaptertest-valid.xml");
        MockUserPrincipal user = new MockUserPrincipal();
        assertEquals(user, adapter.pushRole(user, "SOME_ROLE"));
    }

    private JettyAcegiUserRealm makeAdapter(String fileName)
        throws Exception {
        String useFile = "net/sf/acegisecurity/adapters/" + fileName;

        return new JettyAcegiUserRealm(REALM_NAME, ADAPTER_KEY, useFile);
    }

    //~ Inner Classes ==========================================================

    private class MockUserPrincipal implements UserPrincipal {
        public boolean isAuthenticated() {
            throw new UnsupportedOperationException(
                "mock method not implemented");
        }

        public String getName() {
            throw new UnsupportedOperationException(
                "mock method not implemented");
        }

        public boolean isUserInRole(String arg0) {
            throw new UnsupportedOperationException(
                "mock method not implemented");
        }
    }
}
