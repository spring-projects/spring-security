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

package net.sf.acegisecurity.context;

import junit.framework.TestCase;

import net.sf.acegisecurity.providers.TestingAuthenticationToken;

import org.springframework.context.support.ClassPathXmlApplicationContext;


/**
 * Tests context objects.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class ContextTests extends TestCase {
    //~ Instance fields ========================================================

    private ClassPathXmlApplicationContext ctx;

    //~ Constructors ===========================================================

    public ContextTests() {
        super();
    }

    public ContextTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
        ctx = new ClassPathXmlApplicationContext(
                "/net/sf/acegisecurity/context/applicationContext.xml");
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(ContextTests.class);
    }

    public void testContextInterceptorDetectsEmptyContexts()
        throws Exception {
        Account ben = new Account(1, "ben");
        BankManager bank = (BankManager) ctx.getBean("bankManager");

        try {
            bank.saveAccount(ben);
            fail("Should have thrown ContextHolderEmptyException");
        } catch (ContextHolderEmptyException expected) {
            assertTrue(true);
        }

        Context context = new ContextImpl();
        ContextHolder.setContext(context);

        Account marissa = new Account(2, "marissa");
        bank.saveAccount(marissa);

        ContextHolder.setContext(null);
    }

    public void testContextInterceptorProcessesValidations()
        throws Exception {
        ExoticContext context = new ExoticContext();
        ContextHolder.setContext(context);

        Account ben = new Account(1, "ben");
        BankManager bank = (BankManager) ctx.getBean("bankManager");

        try {
            bank.saveAccount(ben);
            fail(
                "Should have thrown ContextInvalidException (magic number is incorrect)");
        } catch (ContextInvalidException expected) {
            assertTrue(true);
        }

        context.setMagicNumber(7);
        ContextHolder.setContext(context);

        Account marissa = new Account(2, "marissa");
        bank.saveAccount(marissa);

        ContextHolder.setContext(null);
    }

    public void testContextInterceptorValidatesASecureContext()
        throws Exception {
        SecureContext context = new SecureContextImpl();
        ContextHolder.setContext((Context) context);

        Account ben = new Account(1, "ben");
        BankManager bank = (BankManager) ctx.getBean("bankManager");

        try {
            bank.saveAccount(ben);
            fail(
                "Should have thrown ContextInvalidException (no authentication object)");
        } catch (ContextInvalidException expected) {
            assertTrue(true);
        }

        context.setAuthentication(new TestingAuthenticationToken("a", "b", null));
        ContextHolder.setContext((Context) context);

        Account marissa = new Account(2, "marissa");
        bank.saveAccount(marissa);

        ContextHolder.setContext(null);
    }
}
