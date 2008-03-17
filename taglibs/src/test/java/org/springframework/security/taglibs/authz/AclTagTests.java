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

package org.springframework.security.taglibs.authz;

import junit.framework.TestCase;

import org.springframework.security.Authentication;
import org.springframework.security.GrantedAuthority;

import org.springframework.security.acl.AclEntry;
import org.springframework.security.acl.AclManager;
import org.springframework.security.acl.basic.SimpleAclEntry;
import org.springframework.security.acl.basic.AclObjectIdentity;
import org.springframework.security.context.SecurityContextHolder;
import org.springframework.security.providers.TestingAuthenticationToken;

import org.springframework.context.ApplicationContext;
import org.springframework.context.support.StaticApplicationContext;

import javax.servlet.jsp.JspException;
import javax.servlet.jsp.PageContext;
import javax.servlet.jsp.tagext.Tag;


/**
 * Tests {@link AclTag}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class AclTagTests extends TestCase {
    //~ Instance fields ================================================================================================

    private final MyAclTag aclTag = new MyAclTag();

    //~ Methods ========================================================================================================


    protected void tearDown() throws Exception {
        SecurityContextHolder.clearContext();
    }

    public void testInclusionDeniedWhenAclManagerUnawareOfObject() throws JspException {
        Authentication auth = new TestingAuthenticationToken("rod", "koala", new GrantedAuthority[] {});
        SecurityContextHolder.getContext().setAuthentication(auth);

        aclTag.setHasPermission(new Long(SimpleAclEntry.ADMINISTRATION).toString());
        aclTag.setDomainObject(new Integer(54));
        assertEquals(Tag.SKIP_BODY, aclTag.doStartTag());
    }

    public void testInclusionDeniedWhenNoListOfPermissionsGiven() throws JspException {
        Authentication auth = new TestingAuthenticationToken("rod", "koala", new GrantedAuthority[] {});
        SecurityContextHolder.getContext().setAuthentication(auth);

        aclTag.setHasPermission(null);
        aclTag.setDomainObject("object1");
        assertEquals(Tag.SKIP_BODY, aclTag.doStartTag());
    }

    public void testInclusionDeniedWhenPrincipalDoesNotHoldAnyPermissions() throws JspException {
        Authentication auth = new TestingAuthenticationToken("john", "crow", new GrantedAuthority[] {});
        SecurityContextHolder.getContext().setAuthentication(auth);

        aclTag.setHasPermission(new Integer(SimpleAclEntry.ADMINISTRATION) + "," + new Integer(SimpleAclEntry.READ));
        assertEquals(new Integer(SimpleAclEntry.ADMINISTRATION) + "," + new Integer(SimpleAclEntry.READ),
            aclTag.getHasPermission());
        aclTag.setDomainObject("object1");
        assertEquals("object1", aclTag.getDomainObject());
        assertEquals(Tag.SKIP_BODY, aclTag.doStartTag());
    }

    public void testInclusionDeniedWhenPrincipalDoesNotHoldRequiredPermissions() throws JspException {
        Authentication auth = new TestingAuthenticationToken("rod", "koala", new GrantedAuthority[] {});
        SecurityContextHolder.getContext().setAuthentication(auth);

        aclTag.setHasPermission(new Integer(SimpleAclEntry.DELETE).toString());
        aclTag.setDomainObject("object1");
        assertEquals(Tag.SKIP_BODY, aclTag.doStartTag());
    }

    public void testInclusionDeniedWhenSecurityContextEmpty() throws JspException {
        SecurityContextHolder.getContext().setAuthentication(null);

        aclTag.setHasPermission(new Long(SimpleAclEntry.ADMINISTRATION).toString());
        aclTag.setDomainObject("object1");
        assertEquals(Tag.SKIP_BODY, aclTag.doStartTag());
    }

    public void testInclusionPermittedWhenDomainObjectIsNull() throws JspException {
        aclTag.setHasPermission(new Integer(SimpleAclEntry.READ).toString());
        aclTag.setDomainObject(null);
        assertEquals(Tag.EVAL_BODY_INCLUDE, aclTag.doStartTag());
    }

    public void testJspExceptionThrownIfHasPermissionNotValidFormat() throws JspException {
        Authentication auth = new TestingAuthenticationToken("john", "crow", new GrantedAuthority[] {});
        SecurityContextHolder.getContext().setAuthentication(auth);

        aclTag.setHasPermission("0,5, 6"); // shouldn't be any space

        try {
            aclTag.doStartTag();
            fail("Should have thrown JspException");
        } catch (JspException expected) {
            assertTrue(true);
        }
    }

    public void testOperationWhenPrincipalHoldsPermissionOfMultipleList() throws JspException {
        Authentication auth = new TestingAuthenticationToken("rod", "koala", new GrantedAuthority[] {});
        SecurityContextHolder.getContext().setAuthentication(auth);

        aclTag.setHasPermission(new Integer(SimpleAclEntry.ADMINISTRATION) + "," + new Integer(SimpleAclEntry.READ));
        aclTag.setDomainObject("object1");
        assertEquals(Tag.EVAL_BODY_INCLUDE, aclTag.doStartTag());
    }

    public void testOperationWhenPrincipalHoldsPermissionOfSingleList() throws JspException {
        Authentication auth = new TestingAuthenticationToken("rod", "koala", new GrantedAuthority[] {});
        SecurityContextHolder.getContext().setAuthentication(auth);

        aclTag.setHasPermission(new Integer(SimpleAclEntry.READ).toString());
        aclTag.setDomainObject("object1");
        assertEquals(Tag.EVAL_BODY_INCLUDE, aclTag.doStartTag());
    }

    //~ Inner Classes ==================================================================================================

    private class MockAclEntry implements AclEntry {
        // just so AclTag iterates some different types of AclEntrys
    }

    private class MyAclTag extends AclTag {
        protected ApplicationContext getContext(PageContext pageContext) {
            StaticApplicationContext context = new StaticApplicationContext();

            final AclEntry[] acls = new AclEntry[] {
                        new MockAclEntry(),
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
            context.getBeanFactory().registerSingleton("aclManager", aclManager);

            return context;
        }
    }

    private static class MockAclObjectIdentity implements AclObjectIdentity {
    }    
}
