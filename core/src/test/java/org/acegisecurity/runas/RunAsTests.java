/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
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
