/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
 */

package net.sf.acegisecurity.providers.dao.memory;

import junit.framework.TestCase;

import net.sf.acegisecurity.AccessDeniedException;
import net.sf.acegisecurity.BadCredentialsException;
import net.sf.acegisecurity.DisabledException;
import net.sf.acegisecurity.context.Account;
import net.sf.acegisecurity.context.BankManager;
import net.sf.acegisecurity.context.Context;
import net.sf.acegisecurity.context.ContextHolder;
import net.sf.acegisecurity.context.SecureContext;
import net.sf.acegisecurity.context.SecureContextImpl;
import net.sf.acegisecurity.providers.UsernamePasswordAuthenticationToken;

import org.springframework.context.support.ClassPathXmlApplicationContext;


/**
 * Tests {@link DaoAuthenticationProvider} with {@link InMemoryDaoImpl}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class InMemoryDaoTests extends TestCase {
    //~ Instance fields ========================================================

    private ClassPathXmlApplicationContext ctx;

    //~ Constructors ===========================================================

    public InMemoryDaoTests() {
        super();
    }

    public InMemoryDaoTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
        ctx = new ClassPathXmlApplicationContext(
                "/net/sf/acegisecurity/providers/dao/memory/applicationContext.xml");
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(InMemoryDaoTests.class);
    }

    public void testAuthentication() throws Exception {
        Account account = new Account(1, "someone");
        BankManager bank = (BankManager) ctx.getBean("bankManager");

        // Try with an invalid username and password
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("jennifer",
                "zebra");
        SecureContext secureContext = new SecureContextImpl();
        secureContext.setAuthentication(token);
        ContextHolder.setContext((Context) secureContext);

        try {
            bank.saveAccount(account);
            fail("Should have thrown a BadCredentialsException");
        } catch (BadCredentialsException expected) {
            assertTrue(true);
        }

        // Check our token represents itself properly as a String
        System.out.println(token.toString());
        assertTrue(token.toString().length() > 10);

        // Now try with a valid username, but invalid password
        token = new UsernamePasswordAuthenticationToken("marissa", "zebra");
        secureContext.setAuthentication(token);
        ContextHolder.setContext((Context) secureContext);

        try {
            bank.saveAccount(account);
            fail("Should have thrown a BadCredentialsException");
        } catch (BadCredentialsException expected) {
            assertTrue(true);
        }

        // Now try with a valid username and password, but disabled user
        token = new UsernamePasswordAuthenticationToken("dianne", "emu");
        secureContext.setAuthentication(token);
        ContextHolder.setContext((Context) secureContext);

        try {
            bank.saveAccount(account);
            fail("Should have thrown a DisabledException");
        } catch (DisabledException expected) {
            assertTrue(true);
        }

        // Now try as a user who didn't have a password defined, and thus
        // would have been considered invalid at time of creation
        token = new UsernamePasswordAuthenticationToken("someoneelse", "");
        secureContext.setAuthentication(token);
        ContextHolder.setContext((Context) secureContext);

        try {
            bank.saveAccount(account);
            fail("Should have thrown a BadCredentialsException");
        } catch (BadCredentialsException expected) {
            assertTrue(true);
        }

        // Now try as a user who had a password, but no granted authorities,
        // and thus would have been considered invalid at time of creation
        token = new UsernamePasswordAuthenticationToken("someone", "password");
        secureContext.setAuthentication(token);
        ContextHolder.setContext((Context) secureContext);

        try {
            bank.saveAccount(account);
            fail("Should have thrown a BadCredentialsException");
        } catch (BadCredentialsException expected) {
            assertTrue(true);
        }

        // Now try with a valid mixed case username, valid mixed case password,
        // (application context requires passwords to be case matched)
        token = new UsernamePasswordAuthenticationToken("MaRiSsA", "kOaLa");
        secureContext.setAuthentication(token);
        ContextHolder.setContext((Context) secureContext);

        try {
            bank.saveAccount(account);
            fail("Should have thrown a BadCredentialsException");
        } catch (BadCredentialsException expected) {
            assertTrue(true);
        }

        // Now try with a valid mixed case username, correct case password,
        // (application context does not require usernames to be case matched)
        token = new UsernamePasswordAuthenticationToken("MaRiSsA", "koala");
        secureContext.setAuthentication(token);
        ContextHolder.setContext((Context) secureContext);
        bank.saveAccount(account);

        ContextHolder.setContext(null);
    }

    public void testAuthorization() throws Exception {
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
        token = new UsernamePasswordAuthenticationToken("scott", "wombat");
        secureContext.setAuthentication(token);
        ContextHolder.setContext((Context) secureContext);
        bank.loadAccount(account.getId());
        assertTrue(true);

        // Now try as user with ROLE_SUPERVISOR access to the account
        token = new UsernamePasswordAuthenticationToken("marissa", "koala");
        secureContext.setAuthentication(token);
        ContextHolder.setContext((Context) secureContext);
        bank.loadAccount(account.getId());
        assertTrue(true);

        ContextHolder.setContext(null);
    }
}
