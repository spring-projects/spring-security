/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
 */

package net.sf.acegisecurity.adapters;

import junit.framework.TestCase;

import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.AuthenticationManager;
import net.sf.acegisecurity.adapters.jetty.JettyAcegiUserToken;
import net.sf.acegisecurity.providers.ProviderNotFoundException;
import net.sf.acegisecurity.providers.UsernamePasswordAuthenticationToken;

import org.springframework.context.support.ClassPathXmlApplicationContext;


/**
 * Tests {@link AuthByAdapterProvider}
 *
 * @author Ben Alex
 * @version $Id$
 */
public class AuthByAdapterTests extends TestCase {
    //~ Instance fields ========================================================

    private ClassPathXmlApplicationContext ctx;

    //~ Constructors ===========================================================

    public AuthByAdapterTests() {
        super();
    }

    public AuthByAdapterTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
        ctx = new ClassPathXmlApplicationContext(
                "/net/sf/acegisecurity/adapters/applicationContext.xml");
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(AuthByAdapterTests.class);
    }

    public void testAdapterProvider() throws Exception {
        AuthenticationManager authMgr = (AuthenticationManager) ctx.getBean(
                "providerManager");

        // Should authenticate as JettySpringUser is interface of AuthByAdapter
        JettyAcegiUserToken jetty = new JettyAcegiUserToken("my_password",
                "Test", "Password", null);
        Authentication response = authMgr.authenticate(jetty);
        jetty = null;
        assertTrue(true);

        // Should fail as UsernamePassword is not interface of AuthByAdapter
        UsernamePasswordAuthenticationToken user = new UsernamePasswordAuthenticationToken("Test",
                "Password");

        try {
            Authentication response2 = authMgr.authenticate(user);
            fail("Should have thrown ProviderNotFoundException");
        } catch (ProviderNotFoundException expected) {
            assertTrue(true);
        }
    }
}
