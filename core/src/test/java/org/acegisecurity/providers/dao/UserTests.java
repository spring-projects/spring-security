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

package net.sf.acegisecurity.providers.dao;

import junit.framework.TestCase;

import net.sf.acegisecurity.GrantedAuthority;
import net.sf.acegisecurity.GrantedAuthorityImpl;


/**
 * Tests {@link User}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class UserTests extends TestCase {
    //~ Constructors ===========================================================

    public UserTests() {
        super();
    }

    public UserTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(UserTests.class);
    }

    public void testNoArgsConstructor() throws Exception {
        User user = new User();
        assertTrue(true);
    }

    public void testNullValuesRejected() throws Exception {
        try {
            User user = new User(null, "koala", true,
                    new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                            "ROLE_TWO")});
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }

        try {
            User user = new User("marissa", null, true,
                    new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                            "ROLE_TWO")});
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }

        try {
            User user = new User("marissa", "koala", true, null);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testUserGettersSetter() throws Exception {
        User user = new User("marissa", "koala", true,
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")});
        assertEquals("marissa", user.getUsername());
        assertEquals("koala", user.getPassword());
        assertTrue(user.isEnabled());
        assertEquals(new GrantedAuthorityImpl("ROLE_ONE"),
            user.getAuthorities()[0]);
        assertEquals(new GrantedAuthorityImpl("ROLE_TWO"),
            user.getAuthorities()[1]);
    }

    public void testUserIsEnabled() throws Exception {
        User user = new User("marissa", "koala", false,
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")});
        assertTrue(!user.isEnabled());
    }
}
