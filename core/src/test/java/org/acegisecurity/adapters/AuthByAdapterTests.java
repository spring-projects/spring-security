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
