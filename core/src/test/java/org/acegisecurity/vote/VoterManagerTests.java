/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
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

    public void testAffirmative() throws Exception {
        AccessDecisionManager mgr = (AccessDecisionManager) ctx.getBean(
                "affirmativeBased");
        ConfigAttributeDefinition config;
        TestingAuthenticationToken auth;

        auth = new TestingAuthenticationToken("test", "test",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_1"), new GrantedAuthorityImpl(
                        "ROLE_2"), new GrantedAuthorityImpl("ROLE_MAGIC")});

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
    }

    public void testConsensus() throws Exception {
        AccessDecisionManager mgr = (AccessDecisionManager) ctx.getBean(
                "consensusBased");
        ConfigAttributeDefinition config;
        TestingAuthenticationToken auth;

        auth = new TestingAuthenticationToken("test", "test",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_1"), new GrantedAuthorityImpl(
                        "ROLE_2"), new GrantedAuthorityImpl("ROLE_MAGIC")});

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
    }

    public void testUnanimous() throws Exception {
        AccessDecisionManager mgr = (AccessDecisionManager) ctx.getBean(
                "unanimousBased");
        ConfigAttributeDefinition config;
        TestingAuthenticationToken auth;

        auth = new TestingAuthenticationToken("test", "test",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_1"), new GrantedAuthorityImpl(
                        "ROLE_2"), new GrantedAuthorityImpl("ROLE_MAGIC")});

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
    }
}
