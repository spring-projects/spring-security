/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.taglibs.velocity;

import junit.framework.TestCase;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

public class AuthzImplAuthorizeTagTests extends TestCase {
    //~ Instance fields ================================================================================================

    private Authz authz = new AuthzImpl();

    //~ Methods ========================================================================================================

    protected void setUp() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(
                new TestingAuthenticationToken("abc", "123", "ROLE_SUPERVISOR", "ROLE_TELLER"));
    }

    protected void tearDown() throws Exception {
        SecurityContextHolder.clearContext();
    }

    public void testAlwaysReturnsUnauthorizedIfNoUserFound() {
        SecurityContextHolder.getContext().setAuthentication(null);

        //prevents request - no principal in Context
        assertFalse(authz.allGranted("ROLE_TELLER"));
    }

    public void testDefaultsToNotOutputtingBodyWhenNoRequiredAuthorities() {
        //prevents body output - no authorities granted
        assertFalse(authz.allGranted(""));
        assertFalse(authz.anyGranted(""));
        assertFalse(authz.noneGranted(""));
    }

    public void testOutputsBodyIfOneRolePresent() {
        //authorized - ROLE_TELLER in both sets
        assertTrue(authz.anyGranted("ROLE_TELLER"));
    }

    public void testOutputsBodyWhenAllGranted() {
        // allows request - all required roles granted on principal
        assertTrue(authz.allGranted("ROLE_SUPERVISOR,ROLE_TELLER"));
    }

    public void testOutputsBodyWhenNotGrantedSatisfied() {
        // allows request - principal doesn't have ROLE_BANKER
        assertTrue(authz.noneGranted("ROLE_BANKER"));
    }

    public void testPreventsBodyOutputIfNoSecureContext() {
        SecurityContextHolder.getContext().setAuthentication(null);

        // prevents output - no context defined
        assertFalse(authz.anyGranted("ROLE_BANKER"));
    }

    public void testSkipsBodyIfNoAnyRolePresent() {
        // unauthorized - ROLE_BANKER not in granted authorities
        assertFalse(authz.anyGranted("ROLE_BANKER"));
    }

    public void testSkipsBodyWhenMissingAnAllGranted() {
        //  prevents request - missing ROLE_BANKER on principal
        assertFalse(authz.allGranted("ROLE_SUPERVISOR,ROLE_TELLER,ROLE_BANKER"));
    }

    public void testSkipsBodyWhenNotGrantedUnsatisfied() {
        //  prevents request - principal has ROLE_TELLER
        assertFalse(authz.noneGranted("ROLE_TELLER"));
    }
}
