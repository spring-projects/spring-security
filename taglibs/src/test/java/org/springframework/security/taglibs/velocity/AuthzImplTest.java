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

package org.springframework.security.taglibs.velocity;

import junit.framework.TestCase;

import org.springframework.security.Authentication;
import org.springframework.security.GrantedAuthority;

import org.springframework.security.acl.AclEntry;
import org.springframework.security.acl.AclManager;
import org.springframework.security.acl.basic.SimpleAclEntry;
import org.springframework.security.acl.basic.AclObjectIdentity;

import org.springframework.security.context.SecurityContextHolder;

import org.springframework.security.providers.TestingAuthenticationToken;

import org.springframework.security.userdetails.User;

import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.support.StaticApplicationContext;


public class AuthzImplTest extends TestCase {
    //~ Instance fields ================================================================================================

    private Authz authz = new AuthzImpl();
    private ConfigurableApplicationContext ctx;

    //~ Methods ========================================================================================================

    protected void setUp() throws Exception {
        super.setUp();

        ctx = new StaticApplicationContext();

        final AclEntry[] acls = new AclEntry[] {new MockAclEntry(),
                    new SimpleAclEntry("rod", new MockAclObjectIdentity(), null, SimpleAclEntry.ADMINISTRATION),
                    new SimpleAclEntry("rod", new MockAclObjectIdentity(), null, SimpleAclEntry.READ)
        };


        // Create an AclManager
        AclManager aclManager = new AclManager() {
            String object = "object1";
            String principal = "rod";

            public AclEntry[] getAcls(Object domainInstance) {
                return domainInstance.equals(object) ? acls : null;
            }

            public AclEntry[] getAcls(Object domainInstance, Authentication authentication) {
                return domainInstance.equals(object) && authentication.getPrincipal().equals(principal) ? acls : null;
            }
        };

        // Register the AclManager into our ApplicationContext
        ctx.getBeanFactory().registerSingleton("aclManager", aclManager);
    }

    protected void tearDown() throws Exception {
        ctx.close();
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
        Authentication auth = new TestingAuthenticationToken("rod", "koala", new GrantedAuthority[] {});
        SecurityContextHolder.getContext().setAuthentication(auth);

        authz.setAppCtx(ctx);

        boolean result = authz.hasPermission(new Integer(54), new Long(SimpleAclEntry.ADMINISTRATION).toString());

        assertFalse(result);

        SecurityContextHolder.getContext().setAuthentication(null);
    }

    public void testInclusionDeniedWhenNoListOfPermissionsGiven() {
        Authentication auth = new TestingAuthenticationToken("rod", "koala", new GrantedAuthority[] {});
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
        Authentication auth = new TestingAuthenticationToken("rod", "koala", new GrantedAuthority[] {});
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
        Authentication auth = new TestingAuthenticationToken("rod", "koala", new GrantedAuthority[] {});
        SecurityContextHolder.getContext().setAuthentication(auth);

        authz.setAppCtx(ctx);

        String permissions = new Integer(SimpleAclEntry.ADMINISTRATION) + "," + new Integer(SimpleAclEntry.READ);

        boolean result = authz.hasPermission("object1", permissions);

        assertTrue(result);

        SecurityContextHolder.getContext().setAuthentication(null);
    }

    public void testOperationWhenPrincipalHoldsPermissionOfSingleList() {
        Authentication auth = new TestingAuthenticationToken("rod", "koala", new GrantedAuthority[] {});
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
        Authentication auth = new TestingAuthenticationToken("rodAsString", "koala", new GrantedAuthority[] {});
        SecurityContextHolder.getContext().setAuthentication(auth);

        assertEquals("rodAsString", authz.getPrincipal());
    }

    public void testOperationWhenPrincipalIsAUserDetailsInstance() {
        Authentication auth = new TestingAuthenticationToken(new User("rodUserDetails", "koala", true, true, true,
                    true, new GrantedAuthority[] {}), "koala", new GrantedAuthority[] {});
        SecurityContextHolder.getContext().setAuthentication(auth);

        assertEquals("rodUserDetails", authz.getPrincipal());
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

    private static class MockAclObjectIdentity implements AclObjectIdentity {
    }
}
