/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.acegisecurity;

import junit.framework.TestCase;

import org.acegisecurity.AccessDeniedException;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;

import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.context.SecurityContextImpl;

import org.acegisecurity.providers.TestingAuthenticationToken;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;

import org.springframework.context.support.ClassPathXmlApplicationContext;




/**
 * Tests security objects.
 *
 * @author Ben Alex
 * @version $Id: BankTests.java 1496 2006-05-23 13:38:33Z benalex $
 */
public class BankTests extends TestCase {
    //~ Instance fields ================================================================================================

    private BankService service;
    private ClassPathXmlApplicationContext ctx;

    //~ Constructors ===================================================================================================

    public BankTests() {
        super();
    }

    public BankTests(String arg0) {
        super(arg0);
    }

    //~ Methods ========================================================================================================

    private static void createSecureContext() {
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken("test", "test",
                new GrantedAuthority[] {
                    new GrantedAuthorityImpl("ROLE_TELLER"), new GrantedAuthorityImpl("ROLE_PERMISSION_LIST")
                });

        SecurityContextHolder.getContext().setAuthentication(auth);
    }

    private static void destroySecureContext() {
        SecurityContextHolder.setContext(new SecurityContextImpl());
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(BankTests.class);
    }

    public final void setUp() throws Exception {
        super.setUp();
        ctx = new ClassPathXmlApplicationContext("org/acegisecurity/config/auto-config.xml");
        service = (BankService) ctx.getBean("bankService");
    }

    public void testDeniedAccess() throws Exception {
        createSecureContext();

        try {
            service.balance("1");
            fail("Should have thrown AccessDeniedException");
        } catch (AccessDeniedException expected) {
            assertTrue(true);
        }
        destroySecureContext();
    }

    public void testListAccounts() throws Exception {
        createSecureContext();
        service.listAccounts();
        destroySecureContext();
    }
}
