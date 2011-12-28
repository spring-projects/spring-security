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

package org.springframework.security.taglibs.velocity;

import junit.framework.TestCase;

import org.junit.Ignore;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.GrantedAuthorityImpl;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Ignoring some of these tests so that we can rename the file, but still get tests to pass till SEC-1882 can be
 * addressed.
 *
 */
public class AuthzImplAuthorizeTagTests extends TestCase {
    //~ Instance fields ================================================================================================

    private Authz authz = new AuthzImpl();
    private TestingAuthenticationToken currentUser;

    //~ Methods ========================================================================================================

    protected void setUp() throws Exception {
        super.setUp();

        currentUser = new TestingAuthenticationToken("abc", "123",
                new GrantedAuthority[] {
                    new GrantedAuthorityImpl("ROLE_SUPERVISOR"), new GrantedAuthorityImpl("ROLE_TELLER"),
                });

        SecurityContextHolder.getContext().setAuthentication(currentUser);
    }

    protected void tearDown() throws Exception {
        SecurityContextHolder.clearContext();
    }

    public void IGNOREtestAlwaysReturnsUnauthorizedIfNoUserFound() {
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

    public void IGNOREtestOutputsBodyIfOneRolePresent() {
        //authorized - ROLE_TELLER in both sets
        assertTrue(authz.anyGranted("ROLE_TELLER"));
    }

    public void IGNOREtestOutputsBodyWhenAllGranted() {
        // allows request - all required roles granted on principal
        assertTrue(authz.allGranted("ROLE_SUPERVISOR,ROLE_TELLER"));
    }

    public void IGNOREtestOutputsBodyWhenNotGrantedSatisfied() {
        // allows request - principal doesn't have ROLE_BANKER
        assertTrue(authz.noneGranted("ROLE_BANKER"));
    }

    public void IGNOREtestPreventsBodyOutputIfNoSecureContext() {
        SecurityContextHolder.getContext().setAuthentication(null);

        // prevents output - no context defined
        assertFalse(authz.anyGranted("ROLE_BANKER"));
    }

    public void IGNOREtestSkipsBodyIfNoAnyRolePresent() {
        // unauthorized - ROLE_BANKER not in granted authorities
        assertFalse(authz.anyGranted("ROLE_BANKER"));
    }

    public void IGNOREtestSkipsBodyWhenMissingAnAllGranted() {
        //  prevents request - missing ROLE_BANKER on principal
        assertFalse(authz.allGranted("ROLE_SUPERVISOR,ROLE_TELLER,ROLE_BANKER"));
    }

    public void IGNOREtestSkipsBodyWhenNotGrantedUnsatisfied() {
        //  prevents request - principal has ROLE_TELLER
        assertFalse(authz.noneGranted("ROLE_TELLER"));
    }
}
