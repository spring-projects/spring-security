/* Copyright 2004, 2005 Acegi Technology Pty Limited
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

package net.sf.acegisecurity.taglibs.authz;

import junit.framework.TestCase;

import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.GrantedAuthority;
import net.sf.acegisecurity.MockAclManager;
import net.sf.acegisecurity.MockApplicationContext;
import net.sf.acegisecurity.acl.AclEntry;
import net.sf.acegisecurity.acl.AclManager;
import net.sf.acegisecurity.acl.basic.MockAclObjectIdentity;
import net.sf.acegisecurity.acl.basic.SimpleAclEntry;
import net.sf.acegisecurity.context.ContextHolder;
import net.sf.acegisecurity.context.security.SecureContext;
import net.sf.acegisecurity.context.security.SecureContextImpl;
import net.sf.acegisecurity.providers.TestingAuthenticationToken;

import org.springframework.context.ApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;

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
    //~ Instance fields ========================================================

    private final MyAclTag aclTag = new MyAclTag();

    //~ Methods ================================================================

    public void testInclusionDeniedWhenAclManagerUnawareOfObject()
        throws JspException {
        Authentication auth = new TestingAuthenticationToken("marissa",
                "koala", new GrantedAuthority[] {});
        SecureContext sc = new SecureContextImpl();
        sc.setAuthentication(auth);
        ContextHolder.setContext(sc);

        aclTag.setHasPermission(new Long(SimpleAclEntry.ADMINISTRATION)
            .toString());
        aclTag.setDomainObject(new Integer(54));
        assertEquals(Tag.SKIP_BODY, aclTag.doStartTag());

        ContextHolder.setContext(null);
    }

    public void testInclusionDeniedWhenAuthenticationEmpty()
        throws JspException {
        ContextHolder.setContext(new SecureContextImpl());

        aclTag.setHasPermission(new Long(SimpleAclEntry.ADMINISTRATION)
            .toString());
        aclTag.setDomainObject("object1");
        assertEquals(Tag.SKIP_BODY, aclTag.doStartTag());

        ContextHolder.setContext(null);
    }

    public void testInclusionDeniedWhenContextHolderEmpty()
        throws JspException {
        ContextHolder.setContext(null);

        aclTag.setHasPermission(new Long(SimpleAclEntry.ADMINISTRATION)
            .toString());
        aclTag.setDomainObject("object1");
        assertEquals(Tag.SKIP_BODY, aclTag.doStartTag());

        ContextHolder.setContext(null);
    }

    public void testInclusionDeniedWhenNoListOfPermissionsGiven()
        throws JspException {
        Authentication auth = new TestingAuthenticationToken("marissa",
                "koala", new GrantedAuthority[] {});
        SecureContext sc = new SecureContextImpl();
        sc.setAuthentication(auth);
        ContextHolder.setContext(sc);

        aclTag.setHasPermission(null);
        aclTag.setDomainObject("object1");
        assertEquals(Tag.SKIP_BODY, aclTag.doStartTag());

        ContextHolder.setContext(null);
    }

    public void testInclusionDeniedWhenPrincipalDoesNotHoldAnyPermissions()
        throws JspException {
        Authentication auth = new TestingAuthenticationToken("john", "crow",
                new GrantedAuthority[] {});
        SecureContext sc = new SecureContextImpl();
        sc.setAuthentication(auth);
        ContextHolder.setContext(sc);

        aclTag.setHasPermission(new Integer(SimpleAclEntry.ADMINISTRATION)
            + "," + new Integer(SimpleAclEntry.READ));
        assertEquals(new Integer(SimpleAclEntry.ADMINISTRATION) + ","
            + new Integer(SimpleAclEntry.READ), aclTag.getHasPermission());
        aclTag.setDomainObject("object1");
        assertEquals("object1", aclTag.getDomainObject());
        assertEquals(Tag.SKIP_BODY, aclTag.doStartTag());

        ContextHolder.setContext(null);
    }

    public void testInclusionDeniedWhenPrincipalDoesNotHoldRequiredPermissions()
        throws JspException {
        Authentication auth = new TestingAuthenticationToken("marissa",
                "koala", new GrantedAuthority[] {});
        SecureContext sc = new SecureContextImpl();
        sc.setAuthentication(auth);
        ContextHolder.setContext(sc);

        aclTag.setHasPermission(new Integer(SimpleAclEntry.DELETE).toString());
        aclTag.setDomainObject("object1");
        assertEquals(Tag.SKIP_BODY, aclTag.doStartTag());

        ContextHolder.setContext(null);
    }

    public void testInclusionPermittedWhenDomainObjectIsNull()
        throws JspException {
        aclTag.setHasPermission(new Integer(SimpleAclEntry.READ).toString());
        aclTag.setDomainObject(null);
        assertEquals(Tag.EVAL_BODY_INCLUDE, aclTag.doStartTag());
    }

    public void testJspExceptionThrownIfHasPermissionNotValidFormat()
        throws JspException {
        Authentication auth = new TestingAuthenticationToken("john", "crow",
                new GrantedAuthority[] {});
        SecureContext sc = new SecureContextImpl();
        sc.setAuthentication(auth);
        ContextHolder.setContext(sc);

        aclTag.setHasPermission("0,5, 6"); // shouldn't be any space

        try {
            aclTag.doStartTag();
            fail("Should have thrown JspException");
        } catch (JspException expected) {
            assertTrue(true);
        }

        ContextHolder.setContext(null);
    }

    public void testOperationWhenPrincipalHoldsPermissionOfMultipleList()
        throws JspException {
        Authentication auth = new TestingAuthenticationToken("marissa",
                "koala", new GrantedAuthority[] {});
        SecureContext sc = new SecureContextImpl();
        sc.setAuthentication(auth);
        ContextHolder.setContext(sc);

        aclTag.setHasPermission(new Integer(SimpleAclEntry.ADMINISTRATION)
            + "," + new Integer(SimpleAclEntry.READ));
        aclTag.setDomainObject("object1");
        assertEquals(Tag.EVAL_BODY_INCLUDE, aclTag.doStartTag());

        ContextHolder.setContext(null);
    }

    public void testOperationWhenPrincipalHoldsPermissionOfSingleList()
        throws JspException {
        Authentication auth = new TestingAuthenticationToken("marissa",
                "koala", new GrantedAuthority[] {});
        SecureContext sc = new SecureContextImpl();
        sc.setAuthentication(auth);
        ContextHolder.setContext(sc);

        aclTag.setHasPermission(new Integer(SimpleAclEntry.READ).toString());
        aclTag.setDomainObject("object1");
        assertEquals(Tag.EVAL_BODY_INCLUDE, aclTag.doStartTag());

        ContextHolder.setContext(null);
    }

    //~ Inner Classes ==========================================================

    private class MockAclEntry implements AclEntry {
        // just so AclTag iterates some different types of AclEntrys
    }

    private class MyAclTag extends AclTag {
        protected ApplicationContext getContext(PageContext pageContext) {
            ConfigurableApplicationContext context = MockApplicationContext
                .getContext();

            // Create an AclManager
            AclManager aclManager = new MockAclManager("object1", "marissa",
                    new AclEntry[] {new MockAclEntry(), new SimpleAclEntry(
                            "marissa", new MockAclObjectIdentity(), null,
                            SimpleAclEntry.ADMINISTRATION), new SimpleAclEntry(
                            "marissa", new MockAclObjectIdentity(), null,
                            SimpleAclEntry.READ)});

            // Register the AclManager into our ApplicationContext
            context.getBeanFactory().registerSingleton("aclManager", aclManager);

            return context;
        }
    }
}
