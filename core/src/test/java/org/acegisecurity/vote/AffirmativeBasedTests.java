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

package net.sf.acegisecurity.vote;

import junit.framework.TestCase;

import net.sf.acegisecurity.AccessDeniedException;
import net.sf.acegisecurity.ConfigAttributeDefinition;
import net.sf.acegisecurity.GrantedAuthority;
import net.sf.acegisecurity.GrantedAuthorityImpl;
import net.sf.acegisecurity.SecurityConfig;
import net.sf.acegisecurity.providers.TestingAuthenticationToken;

import java.util.List;
import java.util.Vector;


/**
 * Tests {@link AffirmativeBased}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class AffirmativeBasedTests extends TestCase {
    //~ Constructors ===========================================================

    public AffirmativeBasedTests() {
        super();
    }

    public AffirmativeBasedTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(AffirmativeBasedTests.class);
    }

    public void testOneAffirmativeVoteOneDenyVoteOneAbstainVoteGrantsAccess()
        throws Exception {
        TestingAuthenticationToken auth = makeTestToken();
        AffirmativeBased mgr = makeDecisionManager();

        ConfigAttributeDefinition config = new ConfigAttributeDefinition();
        config.addConfigAttribute(new SecurityConfig("ROLE_1")); // grant
        config.addConfigAttribute(new SecurityConfig("DENY_FOR_SURE")); // deny

        mgr.decide(auth, null, config);
        assertTrue(true);
    }

    public void testOneAffirmativeVoteTwoAbstainVotesGrantsAccess()
        throws Exception {
        TestingAuthenticationToken auth = makeTestToken();
        AffirmativeBased mgr = makeDecisionManager();

        ConfigAttributeDefinition config = new ConfigAttributeDefinition();
        config.addConfigAttribute(new SecurityConfig("ROLE_2")); // grant

        mgr.decide(auth, null, config);
        assertTrue(true);
    }

    public void testOneDenyVoteTwoAbstainVotesDeniesAccess()
        throws Exception {
        TestingAuthenticationToken auth = makeTestToken();
        AffirmativeBased mgr = makeDecisionManager();

        ConfigAttributeDefinition config = new ConfigAttributeDefinition();
        config.addConfigAttribute(new SecurityConfig("ROLE_WE_DO_NOT_HAVE")); // deny

        try {
            mgr.decide(auth, null, config);
            fail("Should have thrown AccessDeniedException");
        } catch (AccessDeniedException expected) {
            assertTrue(true);
        }
    }

    public void testThreeAbstainVotesDeniesAccessWithDefault()
        throws Exception {
        TestingAuthenticationToken auth = makeTestToken();
        AffirmativeBased mgr = makeDecisionManager();

        assertTrue(!mgr.isAllowIfAllAbstainDecisions()); // check default

        ConfigAttributeDefinition config = new ConfigAttributeDefinition();
        config.addConfigAttribute(new SecurityConfig("IGNORED_BY_ALL")); // abstain

        try {
            mgr.decide(auth, null, config);
            fail("Should have thrown AccessDeniedException");
        } catch (AccessDeniedException expected) {
            assertTrue(true);
        }
    }

    public void testThreeAbstainVotesGrantsAccessWithoutDefault()
        throws Exception {
        TestingAuthenticationToken auth = makeTestToken();
        AffirmativeBased mgr = makeDecisionManager();
        mgr.setAllowIfAllAbstainDecisions(true);
        assertTrue(mgr.isAllowIfAllAbstainDecisions()); // check changed

        ConfigAttributeDefinition config = new ConfigAttributeDefinition();
        config.addConfigAttribute(new SecurityConfig("IGNORED_BY_ALL")); // abstain

        mgr.decide(auth, null, config);
        assertTrue(true);
    }

    public void testTwoAffirmativeVotesTwoAbstainVotesGrantsAccess()
        throws Exception {
        TestingAuthenticationToken auth = makeTestToken();
        AffirmativeBased mgr = makeDecisionManager();

        ConfigAttributeDefinition config = new ConfigAttributeDefinition();
        config.addConfigAttribute(new SecurityConfig("ROLE_1")); // grant
        config.addConfigAttribute(new SecurityConfig("ROLE_2")); // grant

        mgr.decide(auth, null, config);
        assertTrue(true);
    }

    private AffirmativeBased makeDecisionManager() {
        AffirmativeBased decisionManager = new AffirmativeBased();
        RoleVoter roleVoter = new RoleVoter();
        DenyVoter denyForSureVoter = new DenyVoter();
        DenyAgainVoter denyAgainForSureVoter = new DenyAgainVoter();
        List voters = new Vector();
        voters.add(roleVoter);
        voters.add(denyForSureVoter);
        voters.add(denyAgainForSureVoter);
        decisionManager.setDecisionVoters(voters);

        return decisionManager;
    }

    private TestingAuthenticationToken makeTestToken() {
        return new TestingAuthenticationToken("somebody", "password",
            new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_1"), new GrantedAuthorityImpl(
                    "ROLE_2")});
    }
}
