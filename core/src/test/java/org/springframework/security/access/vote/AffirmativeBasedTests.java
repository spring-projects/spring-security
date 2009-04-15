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

import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.vote.AccessDecisionVoter;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.GrantedAuthorityImpl;


/**
 * Tests {@link AffirmativeBased}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class AffirmativeBasedTests {

    private AffirmativeBased makeDecisionManager() {
        AffirmativeBased decisionManager = new AffirmativeBased();
        RoleVoter roleVoter = new RoleVoter();
        DenyVoter denyForSureVoter = new DenyVoter();
        DenyAgainVoter denyAgainForSureVoter = new DenyAgainVoter();
        List<AccessDecisionVoter> voters = new ArrayList<AccessDecisionVoter>();
        voters.add(roleVoter);
        voters.add(denyForSureVoter);
        voters.add(denyAgainForSureVoter);
        decisionManager.setDecisionVoters(voters);

        return decisionManager;
    }

    private TestingAuthenticationToken makeTestToken() {
        return new TestingAuthenticationToken("somebody", "password",
            new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_1"), new GrantedAuthorityImpl("ROLE_2")});
    }

    @Test
    public void testOneAffirmativeVoteOneDenyVoteOneAbstainVoteGrantsAccess() throws Exception {
        TestingAuthenticationToken auth = makeTestToken();
        AffirmativeBased mgr = makeDecisionManager();

        mgr.decide(auth, new Object(), SecurityConfig.createList(new String[]{"ROLE_1", "DENY_FOR_SURE"}));
    }

    @Test
    public void testOneAffirmativeVoteTwoAbstainVotesGrantsAccess() throws Exception {
        TestingAuthenticationToken auth = makeTestToken();
        AffirmativeBased mgr = makeDecisionManager();

        mgr.decide(auth, new Object(), SecurityConfig.createList("ROLE_2"));
    }

    @Test(expected=AccessDeniedException.class)
    public void testOneDenyVoteTwoAbstainVotesDeniesAccess() throws Exception {
        TestingAuthenticationToken auth = makeTestToken();
        AffirmativeBased mgr = makeDecisionManager();

        mgr.decide(auth, new Object(), SecurityConfig.createList("ROLE_WE_DO_NOT_HAVE"));
    }

    @Test(expected=AccessDeniedException.class)
    public void testThreeAbstainVotesDeniesAccessWithDefault() throws Exception {
        TestingAuthenticationToken auth = makeTestToken();
        AffirmativeBased mgr = makeDecisionManager();

        assertTrue(!mgr.isAllowIfAllAbstainDecisions()); // check default

        mgr.decide(auth, new Object(), SecurityConfig.createList("IGNORED_BY_ALL"));
    }

    @Test
    public void testThreeAbstainVotesGrantsAccessWithoutDefault() throws Exception {
        TestingAuthenticationToken auth = makeTestToken();
        AffirmativeBased mgr = makeDecisionManager();
        mgr.setAllowIfAllAbstainDecisions(true);
        assertTrue(mgr.isAllowIfAllAbstainDecisions()); // check changed

        mgr.decide(auth, new Object(), SecurityConfig.createList("IGNORED_BY_ALL"));
    }

    @Test
    public void testTwoAffirmativeVotesTwoAbstainVotesGrantsAccess() throws Exception {
        TestingAuthenticationToken auth = makeTestToken();
        AffirmativeBased mgr = makeDecisionManager();

        mgr.decide(auth, new Object(), SecurityConfig.createList("ROLE_1", "ROLE_2"));
    }
}
