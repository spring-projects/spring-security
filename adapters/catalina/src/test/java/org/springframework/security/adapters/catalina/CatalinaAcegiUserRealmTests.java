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

package org.springframework.security.adapters.catalina;

import junit.framework.TestCase;

import org.springframework.security.GrantedAuthority;
import org.springframework.security.GrantedAuthorityImpl;

import org.springframework.security.adapters.PrincipalAcegiUserToken;

import org.apache.catalina.LifecycleException;

import java.io.File;

import java.net.URL;

import java.security.Principal;


/**
 * Tests {@link CatalinaAcegiUserRealm}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class CatalinaAcegiUserRealmTests extends TestCase {
    //~ Instance fields ================================================================================================

    private final String ADAPTER_KEY = "my_key";

    //~ Constructors ===================================================================================================

    public CatalinaAcegiUserRealmTests() {
        super();
    }

    public CatalinaAcegiUserRealmTests(String arg0) {
        super(arg0);
    }

    //~ Methods ========================================================================================================

    public static void main(String[] args) {
        junit.textui.TestRunner.run(CatalinaAcegiUserRealmTests.class);
    }

    private CatalinaAcegiUserRealm makeAdapter(String fileName)
        throws Exception {
        CatalinaAcegiUserRealm adapter = new CatalinaAcegiUserRealm();

        URL url = Thread.currentThread().getContextClassLoader().getResource("org/springframework/security/adapters/" + fileName);

        if (url == null) {
            throw new Exception("Could not find " + fileName + " - cannot continue");
        }

        File file = new File(url.getFile());

        System.setProperty("catalina.base", file.getParentFile().getAbsolutePath());
        System.out.println("catalina.base set to: " + System.getProperty("catalina.base"));
        adapter.setAppContextLocation(fileName);
        adapter.setKey(ADAPTER_KEY);
        adapter.startForTest();

        return adapter;
    }

    public final void setUp() throws Exception {
        super.setUp();
    }

    public void testAdapterAbortsIfAppContextDoesNotContainAnAuthenticationBean()
        throws Exception {
        try {
            CatalinaAcegiUserRealm adapter = makeAdapter("catalinaAdapterTest-invalid.xml");
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testAdapterAbortsIfNoAppContextSpecified()
        throws Exception {
        CatalinaAcegiUserRealm adapter = new CatalinaAcegiUserRealm();

        adapter.setKey("KEY");

        try {
            adapter.startForTest();
            fail("Should have thrown LifecycleException");
        } catch (LifecycleException expected) {
            assertEquals("appContextLocation must be defined", expected.getMessage());
        }

        adapter.setAppContextLocation("");

        try {
            adapter.startForTest();
            fail("Should have thrown LifecycleException");
        } catch (LifecycleException expected) {
            assertEquals("appContextLocation must be defined", expected.getMessage());
        }
    }

    public void testAdapterAbortsIfNoKeySpecified() throws Exception {
        CatalinaAcegiUserRealm adapter = new CatalinaAcegiUserRealm();

        adapter.setAppContextLocation("SOMETHING");

        try {
            adapter.startForTest();
            fail("Should have thrown LifecycleException");
        } catch (LifecycleException expected) {
            assertEquals("key must be defined", expected.getMessage());
        }

        adapter.setKey("");

        try {
            adapter.startForTest();
            fail("Should have thrown LifecycleException");
        } catch (LifecycleException expected) {
            assertEquals("key must be defined", expected.getMessage());
        }
    }

    public void testAdapterAbortsWithIncorrectApplicationContextLocation()
        throws Exception {
        CatalinaAcegiUserRealm adapter = new CatalinaAcegiUserRealm();
        adapter.setAppContextLocation("SOME_INVALID_PATH");
        adapter.setKey("KEY");

        try {
            adapter.startForTest();
            fail("Should have thrown LifecycleException");
        } catch (LifecycleException expected) {
            assertTrue(expected.getMessage().startsWith("appContextLocation does not seem to exist in"));
        }
    }

    public void testAdapterIdentifiesItself() throws Exception {
        CatalinaAcegiUserRealm adapter = new CatalinaAcegiUserRealm();
        assertTrue(adapter.getName().lastIndexOf("CatalinaSpringUserRealm") != -1);
    }

    public void testAdapterStartsUpSuccess() throws Exception {
        CatalinaAcegiUserRealm adapter = makeAdapter("catalinaAdapterTest-valid.xml");
        assertTrue(true);
    }

    public void testAuthenticateManyParamsReturnsNull() {
        CatalinaAcegiUserRealm adapter = new CatalinaAcegiUserRealm();
        assertEquals(null, adapter.authenticate(null, null, null, null, null, null, null, null));
    }

    public void testAuthenticateX509ReturnsNull() {
        CatalinaAcegiUserRealm adapter = new CatalinaAcegiUserRealm();
        assertEquals(null, adapter.authenticate(null));
    }

    public void testAuthenticationFailsForIncorrectPassword()
        throws Exception {
        CatalinaAcegiUserRealm adapter = makeAdapter("catalinaAdapterTest-valid.xml");
        assertEquals(null, adapter.authenticate("marissa", "kangaroo"));
    }

    public void testAuthenticationFailsForIncorrectUserName()
        throws Exception {
        CatalinaAcegiUserRealm adapter = makeAdapter("catalinaAdapterTest-valid.xml");
        assertEquals(null, adapter.authenticate("melissa", "koala"));
    }

    public void testAuthenticationUsingByteArrayForCredentials()
        throws Exception {
        CatalinaAcegiUserRealm adapter = makeAdapter("catalinaAdapterTest-valid.xml");
        byte[] credentials = {'k', 'o', 'a', 'l', 'a'};
        Principal result = adapter.authenticate("marissa", credentials);

        if (!(result instanceof PrincipalAcegiUserToken)) {
            fail("Should have returned PrincipalAcegiUserToken");
        }

        PrincipalAcegiUserToken castResult = (PrincipalAcegiUserToken) result;
        assertEquals("marissa", castResult.getPrincipal());
        assertEquals("koala", castResult.getCredentials());
        assertEquals("ROLE_TELLER", castResult.getAuthorities()[0].getAuthority());
        assertEquals("ROLE_SUPERVISOR", castResult.getAuthorities()[1].getAuthority());
        assertEquals(ADAPTER_KEY.hashCode(), castResult.getKeyHash());
    }

    public void testAuthenticationUsingStringForCredentials()
        throws Exception {
        CatalinaAcegiUserRealm adapter = makeAdapter("catalinaAdapterTest-valid.xml");
        Principal result = adapter.authenticate("marissa", "koala");

        if (!(result instanceof PrincipalAcegiUserToken)) {
            fail("Should have returned PrincipalAcegiUserToken");
        }

        PrincipalAcegiUserToken castResult = (PrincipalAcegiUserToken) result;
        assertEquals("marissa", castResult.getPrincipal());
        assertEquals("koala", castResult.getCredentials());
        assertEquals("ROLE_TELLER", castResult.getAuthorities()[0].getAuthority());
        assertEquals("ROLE_SUPERVISOR", castResult.getAuthorities()[1].getAuthority());
        assertEquals(ADAPTER_KEY.hashCode(), castResult.getKeyHash());
    }

    public void testAuthenticationWithNullPasswordHandledGracefully()
        throws Exception {
        CatalinaAcegiUserRealm adapter = makeAdapter("catalinaAdapterTest-valid.xml");
        assertEquals(null, adapter.authenticate("marissa", (String) null));
    }

    public void testAuthenticationWithNullUserNameHandledGracefully()
        throws Exception {
        CatalinaAcegiUserRealm adapter = makeAdapter("catalinaAdapterTest-valid.xml");
        assertEquals(null, adapter.authenticate(null, "koala"));
    }

    public void testGetPasswordReturnsNull() {
        CatalinaAcegiUserRealm adapter = new CatalinaAcegiUserRealm();
        assertEquals(null, adapter.getPassword(null));
    }

    public void testGetPrincipalReturnsNull() {
        CatalinaAcegiUserRealm adapter = new CatalinaAcegiUserRealm();
        assertEquals(null, adapter.getPrincipal(null));
    }

    public void testGetters() {
        CatalinaAcegiUserRealm adapter = new CatalinaAcegiUserRealm();
        adapter.setKey("KEY");
        assertEquals("KEY", adapter.getKey());
        adapter.setAppContextLocation("SOME_LOCATION");
        assertEquals("SOME_LOCATION", adapter.getAppContextLocation());
    }

    public void testHasRoleWithANullPrincipalFails() {
        CatalinaAcegiUserRealm adapter = new CatalinaAcegiUserRealm();
        assertTrue(!adapter.hasRole(null, "ROLE_ONE"));
    }

    public void testHasRoleWithAPrincipalTheAdapterDidNotCreateFails() {
        CatalinaAcegiUserRealm adapter = new CatalinaAcegiUserRealm();
        assertTrue(!adapter.hasRole(new Principal() {
                public String getName() {
                    return "MockPrincipal";
                }
            }, "ROLE_ONE"));
    }

    public void testHasRoleWithPrincipalAcegiUserToken() {
        PrincipalAcegiUserToken token = new PrincipalAcegiUserToken("KEY", "Test", "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl("ROLE_TWO")},
                null);
        CatalinaAcegiUserRealm adapter = new CatalinaAcegiUserRealm();
        assertTrue(adapter.hasRole(token, "ROLE_ONE"));
        assertTrue(adapter.hasRole(token, "ROLE_TWO"));
        assertTrue(!adapter.hasRole(token, "ROLE_WE_DO_NOT_HAVE"));
    }
}
