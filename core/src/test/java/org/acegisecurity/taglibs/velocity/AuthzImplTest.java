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

package org.acegisecurity.taglibs.velocity;

import junit.framework.TestCase;

import org.acegisecurity.Authentication;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.MockAclManager;

import org.acegisecurity.acl.AclEntry;
import org.acegisecurity.acl.AclManager;
import org.acegisecurity.acl.basic.MockAclObjectIdentity;
import org.acegisecurity.acl.basic.SimpleAclEntry;

import org.acegisecurity.context.SecurityContextHolder;

import org.acegisecurity.providers.TestingAuthenticationToken;

import org.acegisecurity.userdetails.User;

import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.support.StaticApplicationContext;


/**
 * DOCUMENT ME!
 */
public class AuthzImplTest extends TestCase {
    //~ Instance fields ================================================================================================

    private Authz authz = new AuthzImpl();
    private ConfigurableApplicationContext ctx;

    //~ Methods ========================================================================================================

    protected void setUp() throws Exception {
        super.setUp();

        /*String[] paths = { "applicationEmpty.xml" };
           ctx = new ClassPathXmlApplicationContext(paths);*/
        ctx = new StaticApplicationContext();

        // Create an AclManager
        AclManager aclManager = new MockAclManager("object1", "marissa",
                new AclEntry[] {
                    new MockAclEntry(),
                    new SimpleAclEntry("marissa", new MockAclObjectIdentity(), null, SimpleAclEntry.ADMINISTRATION),
                    new SimpleAclEntry("marissa", new MockAclObjectIdentity(), null, SimpleAclEntry.READ)
                });

        // Register the AclManager into our ApplicationContext
        ctx.getBeanFactory().registerSingleton("aclManager", aclManager);
    }

    public void testIllegalArgumentExceptionThrownIfHasPermissionNotValidFormat() {
        Authentication auth = new TestingAuthenticationToken("john", "crow", new GrantedAuthority[] {});
        SecurityContextHolder.getContext().setAuthentication(auth);

        authz.setAppCtx(ctx);

        String permissions = "0,5, 6"; // shouldn't be any space

        try {
            authz.hasPermission(null, permissions);
        } catch (IllegalArgumentException iae) {
            assertTrue(true);
        }

        SecurityContextHolder.getContext().setAuthentication(null);
    }

    public void testInclusionDeniedWhenAclManagerUnawareOfObject() {
        Authentication auth = new TestingAuthenticationToken("marissa", "koala", new GrantedAuthority[] {});
        SecurityContextHolder.getContext().setAuthentication(auth);

        authz.setAppCtx(ctx);

        boolean result = authz.hasPermission(new Integer(54), new Long(SimpleAclEntry.ADMINISTRATION).toString());

        assertFalse(result);

        SecurityContextHolder.getContext().setAuthentication(null);
    }

    public void testInclusionDeniedWhenNoListOfPermissionsGiven() {
        Authentication auth = new TestingAuthenticationToken("marissa", "koala", new GrantedAuthority[] {});
        SecurityContextHolder.getContext().setAuthentication(auth);
        authz.setAppCtx(ctx);

        boolean result = authz.hasPermission("object1", null);

        assertFalse(result);

        SecurityContextHolder.getContext().setAuthentication(null);
    }

    public void testInclusionDeniedWhenPrincipalDoesNotHoldAnyPermissions() {
        Authentication auth = new TestingAuthenticationToken("john", "crow", new GrantedAuthority[] {});
        SecurityContextHolder.getContext().setAuthentication(auth);

        authz.setAppCtx(ctx);

        String permissions = new Integer(SimpleAclEntry.ADMINISTRATION) + "," + new Integer(SimpleAclEntry.READ);

        boolean result = authz.hasPermission("object1", permissions);

        assertFalse(result);

        SecurityContextHolder.getContext().setAuthentication(null);
    }

    public void testInclusionDeniedWhenPrincipalDoesNotHoldRequiredPermissions() {
        Authentication auth = new TestingAuthenticationToken("marissa", "koala", new GrantedAuthority[] {});
        SecurityContextHolder.getContext().setAuthentication(auth);
        authz.setAppCtx(ctx);

        String permissions = new Integer(SimpleAclEntry.DELETE).toString();

        boolean result = authz.hasPermission("object1", permissions);

        assertFalse(result);

        SecurityContextHolder.getContext().setAuthentication(null);
    }

    public void testInclusionDeniedWhenSecurityContextEmpty() {
        SecurityContextHolder.getContext().setAuthentication(null);

        authz.setAppCtx(ctx);

        String permissions = new Long(SimpleAclEntry.ADMINISTRATION).toString();

        boolean result = authz.hasPermission("object1", permissions);

        assertFalse(result);

        SecurityContextHolder.getContext().setAuthentication(null);
    }

    public void testInclusionPermittedWhenDomainObjectIsNull() {
        authz.setAppCtx(ctx);

        String permissions = new Integer(SimpleAclEntry.READ).toString();

        boolean result = authz.hasPermission(null, permissions);

        assertTrue(result);
    }

    public void testOperationWhenPrincipalHoldsPermissionOfMultipleList() {
        Authentication auth = new TestingAuthenticationToken("marissa", "koala", new GrantedAuthority[] {});
        SecurityContextHolder.getContext().setAuthentication(auth);

        authz.setAppCtx(ctx);

        String permissions = new Integer(SimpleAclEntry.ADMINISTRATION) + "," + new Integer(SimpleAclEntry.READ);

        boolean result = authz.hasPermission("object1", permissions);

        assertTrue(result);

        SecurityContextHolder.getContext().setAuthentication(null);
    }

    public void testOperationWhenPrincipalHoldsPermissionOfSingleList() {
        Authentication auth = new TestingAuthenticationToken("marissa", "koala", new GrantedAuthority[] {});
        SecurityContextHolder.getContext().setAuthentication(auth);

        authz.setAppCtx(ctx);

        String permissions = new Integer(SimpleAclEntry.READ).toString();

        boolean result = authz.hasPermission("object1", permissions);

        assertTrue(result);
        SecurityContextHolder.getContext().setAuthentication(null);
    }

    /*
     * Test method for 'com.alibaba.exodus2.web.common.security.pulltool.AuthzImpl.getPrincipal()'
     */
    public void testOperationWhenPrincipalIsAString() {
        Authentication auth = new TestingAuthenticationToken("marissaAsString", "koala", new GrantedAuthority[] {});
        SecurityContextHolder.getContext().setAuthentication(auth);

        assertEquals("marissaAsString", authz.getPrincipal());
    }

    public void testOperationWhenPrincipalIsAUserDetailsInstance() {
        Authentication auth = new TestingAuthenticationToken(new User("marissaUserDetails", "koala", true, true, true,
                    true, new GrantedAuthority[] {}), "koala", new GrantedAuthority[] {});
        SecurityContextHolder.getContext().setAuthentication(auth);

        assertEquals("marissaUserDetails", authz.getPrincipal());
    }

    public void testOperationWhenPrincipalIsNull() {
        Authentication auth = new TestingAuthenticationToken(null, "koala", new GrantedAuthority[] {});
        SecurityContextHolder.getContext().setAuthentication(auth);

        assertNull(authz.getPrincipal());
    }

    public void testOperationWhenSecurityContextIsNull() {
        SecurityContextHolder.getContext().setAuthentication(null);

        assertEquals(null, authz.getPrincipal());

        SecurityContextHolder.getContext().setAuthentication(null);
    }

    //~ Inner Classes ==================================================================================================

    private class MockAclEntry implements AclEntry {
        private static final long serialVersionUID = 1L;

        // just so AclTag iterates some different types of AclEntrys
    }
}
