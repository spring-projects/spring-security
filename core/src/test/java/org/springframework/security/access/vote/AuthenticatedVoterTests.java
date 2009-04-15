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

package org.springframework.security.access.vote;

import java.util.List;

import junit.framework.TestCase;

import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.vote.AccessDecisionVoter;
import org.springframework.security.access.vote.AuthenticatedVoter;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.RememberMeAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;


/**
 * Tests {@link AuthenticatedVoter}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class AuthenticatedVoterTests extends TestCase {

    private Authentication createAnonymous() {
        return new AnonymousAuthenticationToken("ignored", "ignored", AuthorityUtils.createAuthorityList("ignored"));
    }

    private Authentication createFullyAuthenticated() {
        return new UsernamePasswordAuthenticationToken("ignored", "ignored", AuthorityUtils.createAuthorityList("ignored"));
    }

    private Authentication createRememberMe() {
        return new RememberMeAuthenticationToken("ignored", "ignored", AuthorityUtils.createAuthorityList("ignored"));
    }

    public void testAnonymousWorks() {
        AuthenticatedVoter voter = new AuthenticatedVoter();
        List<ConfigAttribute> def = SecurityConfig.createList(AuthenticatedVoter.IS_AUTHENTICATED_ANONYMOUSLY);
        assertEquals(AccessDecisionVoter.ACCESS_GRANTED, voter.vote(createAnonymous(), null, def));
        assertEquals(AccessDecisionVoter.ACCESS_GRANTED, voter.vote(createRememberMe(), null, def));
        assertEquals(AccessDecisionVoter.ACCESS_GRANTED, voter.vote(createFullyAuthenticated(), null, def));
    }

    public void testFullyWorks() {
        AuthenticatedVoter voter = new AuthenticatedVoter();
        List<ConfigAttribute> def = SecurityConfig.createList(AuthenticatedVoter.IS_AUTHENTICATED_FULLY);
        assertEquals(AccessDecisionVoter.ACCESS_DENIED, voter.vote(createAnonymous(), null, def));
        assertEquals(AccessDecisionVoter.ACCESS_DENIED, voter.vote(createRememberMe(), null, def));
        assertEquals(AccessDecisionVoter.ACCESS_GRANTED, voter.vote(createFullyAuthenticated(), null, def));
    }

    public void testRememberMeWorks() {
        AuthenticatedVoter voter = new AuthenticatedVoter();
        List<ConfigAttribute> def = SecurityConfig.createList(AuthenticatedVoter.IS_AUTHENTICATED_REMEMBERED);
        assertEquals(AccessDecisionVoter.ACCESS_DENIED, voter.vote(createAnonymous(), null, def));
        assertEquals(AccessDecisionVoter.ACCESS_GRANTED, voter.vote(createRememberMe(), null, def));
        assertEquals(AccessDecisionVoter.ACCESS_GRANTED, voter.vote(createFullyAuthenticated(), null, def));
    }

    public void testSetterRejectsNull() {
        AuthenticatedVoter voter = new AuthenticatedVoter();

        try {
            voter.setAuthenticationTrustResolver(null);
            fail("Expected IAE");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testSupports() {
        AuthenticatedVoter voter = new AuthenticatedVoter();
        assertTrue(voter.supports(String.class));
        assertTrue(voter.supports(new SecurityConfig(AuthenticatedVoter.IS_AUTHENTICATED_ANONYMOUSLY)));
        assertTrue(voter.supports(new SecurityConfig(AuthenticatedVoter.IS_AUTHENTICATED_FULLY)));
        assertTrue(voter.supports(new SecurityConfig(AuthenticatedVoter.IS_AUTHENTICATED_REMEMBERED)));
        assertFalse(voter.supports(new SecurityConfig("FOO")));
    }
}
