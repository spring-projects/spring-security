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

package net.sf.acegisecurity.providers.dao.event;

import junit.framework.TestCase;

import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.GrantedAuthority;
import net.sf.acegisecurity.GrantedAuthorityImpl;
import net.sf.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import net.sf.acegisecurity.providers.dao.User;


/**
 * Tests {@link AuthenticationEvent} and its subclasses.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class AuthenticationEventTests extends TestCase {
    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(AuthenticationEventTests.class);
    }

    public void testDisabledEvent() {
        Authentication auth = getAuthentication();
        User user = getUser();
        AuthenticationFailureDisabledEvent event = new AuthenticationFailureDisabledEvent(auth,
                user);
        assertEquals(auth, event.getAuthentication());
        assertEquals(user, event.getUser());
    }

    public void testPasswordEvent() {
        Authentication auth = getAuthentication();
        User user = getUser();
        AuthenticationFailurePasswordEvent event = new AuthenticationFailurePasswordEvent(auth,
                user);
        assertEquals(auth, event.getAuthentication());
        assertEquals(user, event.getUser());
    }

    public void testRejectsNullAuthentication() {
        try {
            AuthenticationFailureDisabledEvent event = new AuthenticationFailureDisabledEvent(null,
                    getUser());
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testRejectsNullUser() {
        try {
            AuthenticationFailureDisabledEvent event = new AuthenticationFailureDisabledEvent(getAuthentication(),
                    null);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testSuccessEvent() {
        Authentication auth = getAuthentication();
        User user = getUser();
        AuthenticationSuccessEvent event = new AuthenticationSuccessEvent(auth,
                user);
        assertEquals(auth, event.getAuthentication());
        assertEquals(user, event.getUser());
    }

    private Authentication getAuthentication() {
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken("Principal",
                "Credentials");
        authentication.setDetails("127.0.0.1");

        return authentication;
    }

    private User getUser() {
        User user = new User("foo", "bar", true, true, true, true,
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_FOOBAR")});

        return user;
    }
}
