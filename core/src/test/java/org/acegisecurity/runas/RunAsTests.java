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

package net.sf.acegisecurity.runas;

import junit.framework.TestCase;

import net.sf.acegisecurity.AccessDeniedException;
import net.sf.acegisecurity.context.Account;
import net.sf.acegisecurity.context.BankManager;
import net.sf.acegisecurity.context.Context;
import net.sf.acegisecurity.context.ContextHolder;
import net.sf.acegisecurity.context.SecureContext;
import net.sf.acegisecurity.context.SecureContextImpl;
import net.sf.acegisecurity.providers.UsernamePasswordAuthenticationToken;

import org.springframework.context.support.ClassPathXmlApplicationContext;


/**
 * Tests {@link RunAsManagerImpl}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class RunAsTests extends TestCase {
    //~ Instance fields ========================================================

    private ClassPathXmlApplicationContext ctx;

    //~ Constructors ===========================================================

    public RunAsTests() {
        super();
    }

    public RunAsTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
        ctx = new ClassPathXmlApplicationContext(
                "/net/sf/acegisecurity/runas/applicationContext.xml");
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(RunAsTests.class);
    }

    public void testRunAs() throws Exception {
        Account account = new Account(45, "someone");
        BankManager bank = (BankManager) ctx.getBean("bankManager");

        // Try as a user without access to the account
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("peter",
                "opal");
        SecureContext secureContext = new SecureContextImpl();
        secureContext.setAuthentication(token);
        ContextHolder.setContext((Context) secureContext);

        try {
            // NB: account number 45 != granted authority for account 77
            bank.loadAccount(account.getId());
            fail("Should have thrown an AccessDeniedException");
        } catch (AccessDeniedException expected) {
            assertTrue(true);
        }

        // Now try as user with access to account number 45
        // Proves ROLE_RUN_AS_SERVER is being allocated
        token = new UsernamePasswordAuthenticationToken("scott", "wombat");
        secureContext.setAuthentication(token);
        ContextHolder.setContext((Context) secureContext);
        bank.loadAccount(account.getId());
        assertTrue(true);

        // Now try as user with ROLE_SUPERVISOR access to the account
        // Proves ROLE_RUN_AS_SERVER is being allocated
        token = new UsernamePasswordAuthenticationToken("marissa", "koala");
        secureContext.setAuthentication(token);
        ContextHolder.setContext((Context) secureContext);
        bank.loadAccount(account.getId());
        assertTrue(true);

        // Now try to call a method that ROLE_RUN_AS_BACKEND not granted for
        token = new UsernamePasswordAuthenticationToken("marissa", "koala");
        secureContext.setAuthentication(token);
        ContextHolder.setContext((Context) secureContext);

        try {
            bank.saveAccount(account);
            fail("Should have thrown AccessDeniedException");
        } catch (AccessDeniedException expected) {
            assertTrue(true);
        }

        ContextHolder.setContext(null);
    }
}
