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

package net.sf.acegisecurity;

import junit.framework.TestCase;

import net.sf.acegisecurity.context.Account;
import net.sf.acegisecurity.context.BankManager;
import net.sf.acegisecurity.context.Context;
import net.sf.acegisecurity.context.ContextHolder;
import net.sf.acegisecurity.context.ContextImpl;
import net.sf.acegisecurity.context.SecureContext;
import net.sf.acegisecurity.context.SecureContextImpl;
import net.sf.acegisecurity.providers.TestingAuthenticationToken;

import org.springframework.beans.factory.BeanCreationException;

import org.springframework.context.support.ClassPathXmlApplicationContext;


/**
 * Tests security objects.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class SecurityTests extends TestCase {
    //~ Instance fields ========================================================

    private ClassPathXmlApplicationContext ctx;

    //~ Constructors ===========================================================

    public SecurityTests() {
        super();
    }

    public SecurityTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
        ctx = new ClassPathXmlApplicationContext(
                "/net/sf/acegisecurity/applicationContext.xml");
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(SecurityTests.class);
    }

    public void testDetectsInvalidConfigAttribute() throws Exception {
        try {
            ClassPathXmlApplicationContext ctx = new ClassPathXmlApplicationContext(
                    "/net/sf/acegisecurity/badContext.xml");
            fail("Should have thrown BeanCreationException");
        } catch (BeanCreationException expected) {
            assertTrue(true);
        }
    }

    public void testSecurityInterceptorCustomVoter() throws Exception {
        Account marissa = new Account(2, "marissa");
        BankManager bank = (BankManager) ctx.getBean("bankManager");

        // Indicate the authenticated user holds an account number of 65
        GrantedAuthority[] useless = {new GrantedAuthorityImpl("ACCOUNT_65")};
        TestingAuthenticationToken auth = new TestingAuthenticationToken("Peter",
                "emu", useless);
        SecureContext secureContext = new SecureContextImpl();
        secureContext.setAuthentication(auth);
        ContextHolder.setContext((Context) secureContext);

        // Confirm the absence of holding a valid account number rejects access
        try {
            bank.saveAccount(marissa);
            fail("Should have thrown an AccessDeniedException");
        } catch (AccessDeniedException expected) {
            assertTrue(true);
        }

        // Now setup a user with the correct account number
        GrantedAuthority[] account2 = {new GrantedAuthorityImpl("ACCOUNT_2")};
        auth = new TestingAuthenticationToken("Kristy", "opal", account2);
        secureContext.setAuthentication(auth);
        ContextHolder.setContext((Context) secureContext);

        // Check the user can perform operations related to their account number
        bank.loadAccount(marissa.getId());

        ContextHolder.setContext(null);
    }

    public void testSecurityInterceptorDetectsInvalidContexts()
        throws Exception {
        // Normally the security interceptor does not need to detect these conditions,
        // because the context interceptor should with its validate method. However,
        // the security interceptor still checks it is passed the correct objects.
        Account ben = new Account(1, "ben");
        BankManager bank = (BankManager) ctx.getBean("bankManager");

        // First try with a totally empty ContextHolder
        try {
            bank.saveAccount(ben);
            fail(
                "Should have thrown AuthenticationCredentialsNotFoundException");
        } catch (AuthenticationCredentialsNotFoundException expected) {
            assertTrue(true);
        }

        // Now try with a ContextHolder but of the wrong type (not a SecureContext)
        Context context = new ContextImpl();
        ContextHolder.setContext(context);

        try {
            bank.saveAccount(ben);
            fail(
                "Should have thrown AuthenticationCredentialsNotFoundException");
        } catch (AuthenticationCredentialsNotFoundException expected) {
            assertTrue(true);
        }

        // Next try with a SecureContext but without an authentication object in it
        SecureContext secureContext = new SecureContextImpl();
        ContextHolder.setContext((Context) secureContext);

        try {
            bank.saveAccount(ben);
            fail(
                "Should have thrown AuthenticationCredentialsNotFoundException");
        } catch (AuthenticationCredentialsNotFoundException expected) {
            assertTrue(true);
        }

        // Now try with a SecureContext, correctly setup, which should work
        GrantedAuthority[] granted = {new GrantedAuthorityImpl(
                "ROLE_SUPERVISOR")};
        TestingAuthenticationToken auth = new TestingAuthenticationToken("Jeni",
                "kangaroo", granted);
        secureContext.setAuthentication(auth);
        ContextHolder.setContext((Context) secureContext);

        Account marissa = new Account(2, "marissa");
        marissa.deposit(2000);
        bank.saveAccount(marissa);
        assertTrue(2000 == bank.getBalance(marissa.getId()));

        // Now confirm if we subclass SecureContextImpl it still works.
        // Note the validate method in our ExoticSecureContext will not be
        // called, as we do not have the context interceptor defined.
        ExoticSecureContext exoticContext = new ExoticSecureContext();
        exoticContext.setAuthentication(auth);
        ContextHolder.setContext((Context) secureContext);

        Account scott = new Account(3, "scott");
        scott.deposit(50);
        bank.saveAccount(scott);
        assertTrue(50 == bank.getBalance(scott.getId()));

        ContextHolder.setContext(null);
    }

    public void testSecurityInterceptorEnforcesRoles()
        throws Exception {
        Account ben = new Account(1, "ben");
        ben.deposit(25);

        BankManager bank = (BankManager) ctx.getBean("bankManager");

        // Indicate the authenticated user holds a role that is not useful
        GrantedAuthority[] useless = {new GrantedAuthorityImpl(
                "ROLE_NOTHING_USEFUL")};
        TestingAuthenticationToken auth = new TestingAuthenticationToken("George",
                "koala", useless);
        SecureContext secureContext = new SecureContextImpl();
        secureContext.setAuthentication(auth);
        ContextHolder.setContext((Context) secureContext);

        // Confirm the absence of holding a valid role rejects access
        try {
            bank.saveAccount(ben);
            fail("Should have thrown an AccessDeniedException");
        } catch (AccessDeniedException expected) {
            assertTrue(true);
        }

        // Now try to call a public method (getBankFundsUnderControl)
        bank.getBankFundsUnderControl();

        // Now setup a user with only a teller role
        GrantedAuthority[] teller = {new GrantedAuthorityImpl("ROLE_TELLER")};
        auth = new TestingAuthenticationToken("Michelle", "wombat", teller);
        secureContext.setAuthentication(auth);
        ContextHolder.setContext((Context) secureContext);

        // Confirm the absence of ROLE_SUPERVISOR prevents calling deleteAccount
        try {
            bank.deleteAccount(ben.getId());
            fail("Should have thrown an AccessDeniedException");
        } catch (AccessDeniedException expected) {
            assertTrue(true);
        }

        // Check the teller can perform ROLE_TELLER secured operations
        bank.saveAccount(ben);
        assertTrue(25 == bank.getBalance(ben.getId()));

        ContextHolder.setContext(null);
    }
}
