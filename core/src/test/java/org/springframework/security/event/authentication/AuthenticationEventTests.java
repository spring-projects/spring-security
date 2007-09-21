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

package org.springframework.security.event.authentication;

import junit.framework.TestCase;

import org.springframework.security.Authentication;
import org.springframework.security.AuthenticationException;
import org.springframework.security.DisabledException;

import org.springframework.security.providers.UsernamePasswordAuthenticationToken;


/**
 * Tests {@link AbstractAuthenticationEvent} and its subclasses.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class AuthenticationEventTests extends TestCase {
    //~ Methods ========================================================================================================

    private Authentication getAuthentication() {
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken("Principal",
                "Credentials");
        authentication.setDetails("127.0.0.1");

        return authentication;
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(AuthenticationEventTests.class);
    }

    public final void setUp() throws Exception {
        super.setUp();
    }

    public void testAbstractAuthenticationEvent() {
        Authentication auth = getAuthentication();
        AbstractAuthenticationEvent event = new AuthenticationSuccessEvent(auth);
        assertEquals(auth, event.getAuthentication());
    }

    public void testAbstractAuthenticationFailureEvent() {
        Authentication auth = getAuthentication();
        AuthenticationException exception = new DisabledException("TEST");
        AbstractAuthenticationFailureEvent event = new AuthenticationFailureDisabledEvent(auth, exception);
        assertEquals(auth, event.getAuthentication());
        assertEquals(exception, event.getException());
    }

    public void testRejectsNullAuthentication() {
        AuthenticationException exception = new DisabledException("TEST");

        try {
            AuthenticationFailureDisabledEvent event = new AuthenticationFailureDisabledEvent(null, exception);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testRejectsNullAuthenticationException() {
        try {
            new AuthenticationFailureDisabledEvent(getAuthentication(), null);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }
}
