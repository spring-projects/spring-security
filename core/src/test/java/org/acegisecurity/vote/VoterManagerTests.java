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

import net.sf.acegisecurity.AccessDecisionManager;
import net.sf.acegisecurity.AccessDeniedException;
import net.sf.acegisecurity.ConfigAttributeDefinition;
import net.sf.acegisecurity.GrantedAuthority;
import net.sf.acegisecurity.GrantedAuthorityImpl;
import net.sf.acegisecurity.SecurityConfig;
import net.sf.acegisecurity.providers.TestingAuthenticationToken;

import org.springframework.context.support.ClassPathXmlApplicationContext;

import java.util.List;
import java.util.Vector;


/**
 * Tests voter decision managers.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class VoterManagerTests extends TestCase {
    //~ Instance fields ========================================================

    private ClassPathXmlApplicationContext ctx;

    //~ Constructors ===========================================================

    public VoterManagerTests() {
        super();
    }

    public VoterManagerTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
        ctx = new ClassPathXmlApplicationContext(
                "/net/sf/acegisecurity/vote/applicationContext.xml");
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(VoterManagerTests.class);
    }

    public void testAbstractAccessDecisionManagerSetter()
        throws Exception {
        AffirmativeBased affirmative = new AffirmativeBased();
        affirmative.setAllowIfAllAbstainDecisions(false);
        assertTrue(!affirmative.isAllowIfAllAbstainDecisions());
        affirmative.setAllowIfAllAbstainDecisions(true);
        assertTrue(affirmative.isAllowIfAllAbstainDecisions());
    }

    public void testAbstractAccessDecisionManagerVoterListHandling()
        throws Exception {
        XVoter x = new XVoter();
        List xVoterList = new Vector();
        xVoterList.add(x);

        AffirmativeBased affirmative = new AffirmativeBased();
        affirmative.setDecisionVoters(xVoterList);

        try {
            affirmative.setDecisionVoters(null);
            fail("Should have thrown IllegalArgumentException as list null");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }

        List sampleList = new Vector();

        try {
            affirmative.setDecisionVoters(sampleList);
            fail("Should have thrown IllegalArgumentException as list empty");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }

        sampleList.add(x); // valid (is AccessDecisionVoter)
        sampleList.add("Hello world"); // invalid (not AccessDecisionVoter)

        try {
            affirmative.setDecisionVoters(sampleList);
            fail(
                "Should have thrown IllegalArgumentException as list has invalid entries");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testAffirmative() throws Exception {
        AffirmativeBased mgr = (AffirmativeBased) ctx.getBean(
                "affirmativeBased");
        ConfigAttributeDefinition config;
        TestingAuthenticationToken auth;

        auth = new TestingAuthenticationToken("test", "test",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_1"), new GrantedAuthorityImpl(
                        "ROLE_2"), new GrantedAuthorityImpl("ROLE_MAGIC")});

        // Check if we'd be given access, even with a definite deny vote
        config = new ConfigAttributeDefinition();
        config.addConfigAttribute(new SecurityConfig("ROLE_2")); // grant
        config.addConfigAttribute(new SecurityConfig("DENY_FOR_SURE")); // deny
        mgr.decide(auth, null, config);
        assertTrue(true);

        // Check if we'd be denied access, with only one definite deny vote
        config = new ConfigAttributeDefinition();
        config.addConfigAttribute(new SecurityConfig("DENY_FOR_SURE")); // deny

        try {
            mgr.decide(auth, null, config);
            fail("Should have thrown AccessDeniedException");
        } catch (AccessDeniedException expected) {
            assertTrue(true);
        }

        // Check if we'd get access if ROLE_2 was all that is acceptable
        config = new ConfigAttributeDefinition();
        config.addConfigAttribute(new SecurityConfig("ROLE_2")); // grant
        mgr.decide(auth, null, config);
        assertTrue(true);

        // Check if we'd get access if YYYY was all that is acceptable
        config = new ConfigAttributeDefinition();
        config.addConfigAttribute(new SecurityConfig("YYYY")); // grant
        mgr.decide(auth, null, config);
        assertTrue(true);

        // Check if we'd get access if everything was acceptable
        config = new ConfigAttributeDefinition();
        config.addConfigAttribute(new SecurityConfig("ROLE_1")); // grant and return
        config.addConfigAttribute(new SecurityConfig("ROLE_2")); // not tested
        config.addConfigAttribute(new SecurityConfig("XXXX")); // grant
        config.addConfigAttribute(new SecurityConfig("YYYY")); // grant
        mgr.decide(auth, null, config);
        assertTrue(true);

        // Check if we'd get denied access if ROLE_9 was acceptable
        config = new ConfigAttributeDefinition();
        config.addConfigAttribute(new SecurityConfig("ROLE_9")); // deny

        try {
            mgr.decide(auth, null, config);
            fail("Should have thrown AccessDeniedException");
        } catch (AccessDeniedException expected) {
            assertTrue(true);
        }

        auth = new TestingAuthenticationToken("test", "test",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_1"), new GrantedAuthorityImpl(
                        "ROLE_2"),});

        // Check if we'd get access if ROLE_1 and 2 was acceptable
        config = new ConfigAttributeDefinition();
        config.addConfigAttribute(new SecurityConfig("ROLE_1")); // grant and return
        config.addConfigAttribute(new SecurityConfig("ROLE_2")); // not tested
        mgr.decide(auth, null, config);
        assertTrue(true);

        // Check if we'd get granted access even if one returned deny
        config = new ConfigAttributeDefinition();
        config.addConfigAttribute(new SecurityConfig("ROLE_1")); // grant and return
        config.addConfigAttribute(new SecurityConfig("ROLE_2")); // not tested
        config.addConfigAttribute(new SecurityConfig("XXXX")); // deny
        mgr.decide(auth, null, config);
        assertTrue(true);

        // Check if we'd get denied access if all returned deny
        config = new ConfigAttributeDefinition();
        config.addConfigAttribute(new SecurityConfig("YYYY")); // deny

        try {
            mgr.decide(auth, null, config);
            fail("Should have thrown AccessDeniedException");
        } catch (AccessDeniedException expected) {
            assertTrue(true);
        }

        // Check if we'd be denied access if all abstained
        config = new ConfigAttributeDefinition();
        config.addConfigAttribute(new SecurityConfig("NONE_WILL_VOTE")); // abstain

        try {
            mgr.decide(auth, null, config);
            fail("Should have thrown AccessDeniedException");
        } catch (AccessDeniedException expected) {
            assertTrue(true);
        }

        // Now check it works given we approve access if all abstain
        mgr.setAllowIfAllAbstainDecisions(true);
        mgr.decide(auth, null, config);
        assertTrue(true);
    }

    public void testConsensus() throws Exception {
        ConsensusBased mgr = (ConsensusBased) ctx.getBean("consensusBased");
        ConfigAttributeDefinition config;
        TestingAuthenticationToken auth;

        auth = new TestingAuthenticationToken("test", "test",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_1"), new GrantedAuthorityImpl(
                        "ROLE_2"), new GrantedAuthorityImpl("ROLE_MAGIC")});

        // Check if we'd be given access, even with a definite deny vote
        config = new ConfigAttributeDefinition();
        config.addConfigAttribute(new SecurityConfig("ROLE_2")); // grant
        config.addConfigAttribute(new SecurityConfig("DENY_FOR_SURE")); // deny
        mgr.decide(auth, null, config);
        assertTrue(true);

        // Check if we'd be denied access, with only one definite deny vote
        config = new ConfigAttributeDefinition();
        config.addConfigAttribute(new SecurityConfig("DENY_FOR_SURE")); // deny

        try {
            mgr.decide(auth, null, config);
            fail("Should have thrown AccessDeniedException");
        } catch (AccessDeniedException expected) {
            assertTrue(true);
        }

        // Check if we'd get access if ROLE_2 was all that is acceptable
        config = new ConfigAttributeDefinition();
        config.addConfigAttribute(new SecurityConfig("ROLE_2")); // grant
        mgr.decide(auth, null, config);
        assertTrue(true);

        // Check if we'd get access if YYYY was all that is acceptable
        config = new ConfigAttributeDefinition();
        config.addConfigAttribute(new SecurityConfig("YYYY")); // grant
        mgr.decide(auth, null, config);
        assertTrue(true);

        // Check if we'd get access if everything was acceptable
        config = new ConfigAttributeDefinition();
        config.addConfigAttribute(new SecurityConfig("ROLE_1")); // grant and return
        config.addConfigAttribute(new SecurityConfig("ROLE_2")); // not tested
        config.addConfigAttribute(new SecurityConfig("XXXX")); // grant
        config.addConfigAttribute(new SecurityConfig("YYYY")); // grant
        mgr.decide(auth, null, config);
        assertTrue(true);

        // Check if we'd get denied access if ROLE_9 was acceptable
        config = new ConfigAttributeDefinition();
        config.addConfigAttribute(new SecurityConfig("ROLE_9")); // deny

        try {
            mgr.decide(auth, null, config);
            fail("Should have thrown AccessDeniedException");
        } catch (AccessDeniedException expected) {
            assertTrue(true);
        }

        auth = new TestingAuthenticationToken("test", "test",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_1"), new GrantedAuthorityImpl(
                        "ROLE_2"),});

        // Check if we'd get access if ROLE_1 and 2 was acceptable
        config = new ConfigAttributeDefinition();
        config.addConfigAttribute(new SecurityConfig("ROLE_1")); // grant and return
        config.addConfigAttribute(new SecurityConfig("ROLE_2")); // not tested
        mgr.decide(auth, null, config);
        assertTrue(true);

        // Check if we'd get granted access even if one returned deny
        config = new ConfigAttributeDefinition();
        config.addConfigAttribute(new SecurityConfig("ROLE_1")); // grant and return
        config.addConfigAttribute(new SecurityConfig("ROLE_2")); // not tested
        config.addConfigAttribute(new SecurityConfig("XXXX")); // deny
        mgr.decide(auth, null, config);
        assertTrue(true);

        // Check if we'd get denied access if all returned deny
        config = new ConfigAttributeDefinition();
        config.addConfigAttribute(new SecurityConfig("XXXX")); // deny

        try {
            mgr.decide(auth, null, config);
            fail("Should have thrown AccessDeniedException");
        } catch (AccessDeniedException expected) {
            assertTrue(true);
        }

        // Check if we'd get denied access if equal votes, after changing setting
        assertTrue(mgr.isAllowIfEqualGrantedDeniedDecisions()); // check default
        mgr.setAllowIfEqualGrantedDeniedDecisions(false);
        config = new ConfigAttributeDefinition();
        config.addConfigAttribute(new SecurityConfig("ROLE_1")); // grant
        config.addConfigAttribute(new SecurityConfig("DENY_FOR_SURE")); // deny

        try {
            mgr.decide(auth, null, config);
            fail("Should have thrown AccessDeniedException");
        } catch (AccessDeniedException expected) {
            assertTrue(true);
        }

        // Check if we'd be denied access if all abstained
        config = new ConfigAttributeDefinition();
        config.addConfigAttribute(new SecurityConfig("NONE_WILL_VOTE")); // abstain

        try {
            mgr.decide(auth, null, config);
            fail("Should have thrown AccessDeniedException");
        } catch (AccessDeniedException expected) {
            assertTrue(true);
        }

        // Now check it works given we approve access if all abstain
        mgr.setAllowIfAllAbstainDecisions(true);
        mgr.decide(auth, null, config);
        assertTrue(true);
    }

    public void testUnanimous() throws Exception {
        UnanimousBased mgr = (UnanimousBased) ctx.getBean("unanimousBased");
        ConfigAttributeDefinition config;
        TestingAuthenticationToken auth;

        auth = new TestingAuthenticationToken("test", "test",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_1"), new GrantedAuthorityImpl(
                        "ROLE_2"), new GrantedAuthorityImpl("ROLE_MAGIC")});

        // Check if we'd be denied access, with only one definite deny vote and many affirmative
        config = new ConfigAttributeDefinition();
        config.addConfigAttribute(new SecurityConfig("DENY_FOR_SURE")); // deny
        config.addConfigAttribute(new SecurityConfig("ROLE_2")); // grant
        config.addConfigAttribute(new SecurityConfig("ROLE_1")); // grant

        try {
            mgr.decide(auth, null, config);
            fail("Should have thrown AccessDeniedException");
        } catch (AccessDeniedException expected) {
            assertTrue(true);
        }

        // Check if we'd get access if ROLE_2 was all that is required
        config = new ConfigAttributeDefinition();
        config.addConfigAttribute(new SecurityConfig("ROLE_2")); // grant
        mgr.decide(auth, null, config);
        assertTrue(true);

        // Check if we'd get access if YYYY was all that is required
        config = new ConfigAttributeDefinition();
        config.addConfigAttribute(new SecurityConfig("YYYY")); // grant
        mgr.decide(auth, null, config);
        assertTrue(true);

        // Check if we'd get access if everything was required
        config = new ConfigAttributeDefinition();
        config.addConfigAttribute(new SecurityConfig("ROLE_1")); // grant
        config.addConfigAttribute(new SecurityConfig("ROLE_2")); // grant
        config.addConfigAttribute(new SecurityConfig("XXXX")); // grant
        config.addConfigAttribute(new SecurityConfig("YYYY")); // grant
        mgr.decide(auth, null, config);
        assertTrue(true);

        // Check if we'd get denied access if ROLE_9 was required
        config = new ConfigAttributeDefinition();
        config.addConfigAttribute(new SecurityConfig("ROLE_9")); // deny

        try {
            mgr.decide(auth, null, config);
            fail("Should have thrown AccessDeniedException");
        } catch (AccessDeniedException expected) {
            assertTrue(true);
        }

        auth = new TestingAuthenticationToken("test", "test",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_1"), new GrantedAuthorityImpl(
                        "ROLE_2"),});

        // Check if we'd get access if ROLE_1 and 2 was required
        config = new ConfigAttributeDefinition();
        config.addConfigAttribute(new SecurityConfig("ROLE_1")); // grant
        config.addConfigAttribute(new SecurityConfig("ROLE_2")); // grant
        mgr.decide(auth, null, config);
        assertTrue(true);

        // Check if we'd get denied access if all any return deny at all
        config = new ConfigAttributeDefinition();
        config.addConfigAttribute(new SecurityConfig("ROLE_1")); // grant
        config.addConfigAttribute(new SecurityConfig("ROLE_2")); // grant
        config.addConfigAttribute(new SecurityConfig("XXXX")); // deny

        try {
            mgr.decide(auth, null, config);
            fail("Should have thrown AccessDeniedException");
        } catch (AccessDeniedException expected) {
            assertTrue(true);
        }

        // Check if we'd be denied access if all abstained
        config = new ConfigAttributeDefinition();
        config.addConfigAttribute(new SecurityConfig("NONE_WILL_VOTE")); // abstain

        try {
            mgr.decide(auth, null, config);
            fail("Should have thrown AccessDeniedException");
        } catch (AccessDeniedException expected) {
            assertTrue(true);
        }

        // Now check it works given we approve access if all abstain
        mgr.setAllowIfAllAbstainDecisions(true);
        mgr.decide(auth, null, config);
        assertTrue(true);
    }
}
