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

package org.springframework.security;

import junit.framework.TestCase;

import org.springframework.security.AccessDeniedException;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.GrantedAuthorityImpl;

import org.springframework.security.context.SecurityContextHolder;
import org.springframework.security.context.SecurityContextImpl;

import org.springframework.security.providers.UsernamePasswordAuthenticationToken;

import org.springframework.context.support.ClassPathXmlApplicationContext;




/**
 * Tests security objects.
 *
 * @author Ben Alex
 * @version $Id$
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
        ctx = new ClassPathXmlApplicationContext("org/security/config/auto-config.xml");
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
