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

package org.acegisecurity.adapters;

import junit.framework.TestCase;

import org.acegisecurity.Authentication;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;

import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;


/**
 * Tests {@link AuthByAdapterProvider}
 *
 * @author Ben Alex
 * @version $Id$
 */
public class AuthByAdapterTests extends TestCase {
    //~ Constructors ===========================================================

    public AuthByAdapterTests() {
        super();
    }

    public AuthByAdapterTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(AuthByAdapterTests.class);
    }

    public void testAuthByAdapterProviderCorrectAuthenticationOperation()
        throws Exception {
        AuthByAdapterProvider provider = new AuthByAdapterProvider();
        provider.setKey("my_password");

        PrincipalAcegiUserToken token = new PrincipalAcegiUserToken("my_password",
                "Test", "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")}, null);
        assertTrue(provider.supports(token.getClass()));

        Authentication response = provider.authenticate(token);
        assertTrue(true);

        assertEquals(token.getCredentials(), response.getCredentials());
        assertEquals(token.getPrincipal(), response.getPrincipal());
        assertEquals(token.getAuthorities(), response.getAuthorities());

        if (!response.getClass().equals(token.getClass())) {
            fail("Should have returned same type of object it was given");
        }

        PrincipalAcegiUserToken castResponse = (PrincipalAcegiUserToken) response;
        assertEquals(token.getName(), castResponse.getName());
    }

    public void testAuthByAdapterProviderNonAuthenticationMethods()
        throws Exception {
        AuthByAdapterProvider provider = new AuthByAdapterProvider();

        try {
            provider.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException as key not set");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }

        provider.setKey("my_password");
        provider.afterPropertiesSet();
        assertTrue(true);

        assertEquals("my_password", provider.getKey());
    }

    public void testAuthByAdapterProviderOnlyAcceptsAuthByAdapterImplementations()
        throws Exception {
        AuthByAdapterProvider provider = new AuthByAdapterProvider();
        provider.setKey("my_password");

        // Should fail as UsernamePassword is not interface of AuthByAdapter
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("Test",
                "Password");

        assertTrue(!provider.supports(token.getClass()));

        try {
            provider.authenticate(token);
            fail(
                "Should have thrown ClassCastException (supports() false response was ignored)");
        } catch (ClassCastException expected) {
            assertTrue(true);
        }
    }

    public void testAuthByAdapterProviderRequiresCorrectKey()
        throws Exception {
        AuthByAdapterProvider provider = new AuthByAdapterProvider();
        provider.setKey("my_password");

        // Should fail as PrincipalAcegiUserToken has different key
        PrincipalAcegiUserToken token = new PrincipalAcegiUserToken("wrong_password",
                "Test", "Password", null, null);

        try {
            provider.authenticate(token);
            fail("Should have thrown BadCredentialsException");
        } catch (BadCredentialsException expected) {
            assertTrue(true);
        }
    }
}
