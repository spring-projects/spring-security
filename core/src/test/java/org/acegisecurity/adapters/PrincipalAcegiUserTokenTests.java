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

package org.acegisecurity.adapters;

import junit.framework.TestCase;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;


/**
 * Tests {@link PrincipalAcegiUserToken}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class PrincipalAcegiUserTokenTests extends TestCase {
    //~ Constructors ===================================================================================================

    public PrincipalAcegiUserTokenTests() {
        super();
    }

    public PrincipalAcegiUserTokenTests(String arg0) {
        super(arg0);
    }

    //~ Methods ========================================================================================================

    public static void main(String[] args) {
        junit.textui.TestRunner.run(PrincipalAcegiUserTokenTests.class);
    }

    public final void setUp() throws Exception {
        super.setUp();
    }

    public void testGetters() throws Exception {
        PrincipalAcegiUserToken token = new PrincipalAcegiUserToken("my_password", "Test", "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl("ROLE_TWO")},
                null);
        assertEquals("Test", token.getPrincipal());
        assertEquals("Password", token.getCredentials());
        assertEquals("my_password".hashCode(), token.getKeyHash());
        assertEquals("Test", token.getName());
    }

    public void testNoArgConstructorDoesntExist() {
        Class clazz = PrincipalAcegiUserToken.class;

        try {
            clazz.getDeclaredConstructor((Class[]) null);
            fail("Should have thrown NoSuchMethodException");
        } catch (NoSuchMethodException expected) {
            assertTrue(true);
        }
    }
}
