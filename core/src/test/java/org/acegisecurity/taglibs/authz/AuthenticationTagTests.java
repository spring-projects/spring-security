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

package net.sf.acegisecurity.taglibs.authz;

import junit.framework.TestCase;

import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.GrantedAuthority;
import net.sf.acegisecurity.context.ContextHolder;
import net.sf.acegisecurity.context.SecureContext;
import net.sf.acegisecurity.context.SecureContextImpl;
import net.sf.acegisecurity.providers.TestingAuthenticationToken;
import net.sf.acegisecurity.providers.dao.User;

import javax.servlet.jsp.JspException;
import javax.servlet.jsp.tagext.Tag;


/**
 * Tests {@link AuthenticationTag}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class AuthenticationTagTests extends TestCase {
    //~ Instance fields ========================================================

    private final MyAuthenticationTag authenticationTag = new MyAuthenticationTag();

    //~ Methods ================================================================

    public void testOperationWhenAuthenticationIsNull()
        throws JspException {
        ContextHolder.setContext(new SecureContextImpl());

        authenticationTag.setOperation("principal");
        assertEquals(Tag.SKIP_BODY, authenticationTag.doStartTag());
        assertEquals(null, authenticationTag.getLastMessage());

        ContextHolder.setContext(null);
    }

    public void testOperationWhenContextHolderIsNull()
        throws JspException {
        ContextHolder.setContext(null);

        authenticationTag.setOperation("principal");
        assertEquals(Tag.SKIP_BODY, authenticationTag.doStartTag());
        assertEquals(null, authenticationTag.getLastMessage());
    }

    public void testOperationWhenPrincipalIsAString() throws JspException {
        Authentication auth = new TestingAuthenticationToken("marissaAsString",
                "koala", new GrantedAuthority[] {});
        SecureContext sc = new SecureContextImpl();
        sc.setAuthentication(auth);
        ContextHolder.setContext(sc);

        authenticationTag.setOperation("principal");
        assertEquals(Tag.SKIP_BODY, authenticationTag.doStartTag());
        assertEquals("marissaAsString", authenticationTag.getLastMessage());
    }

    public void testOperationWhenPrincipalIsAUserDetailsInstance()
        throws JspException {
        Authentication auth = new TestingAuthenticationToken(new User(
                    "marissaUserDetails", "koala", true, true, true,
                    new GrantedAuthority[] {}), "koala",
                new GrantedAuthority[] {});
        SecureContext sc = new SecureContextImpl();
        sc.setAuthentication(auth);
        ContextHolder.setContext(sc);

        authenticationTag.setOperation("principal");
        assertEquals(Tag.SKIP_BODY, authenticationTag.doStartTag());
        assertEquals("marissaUserDetails", authenticationTag.getLastMessage());
    }

    public void testOperationWhenPrincipalIsNull() throws JspException {
        Authentication auth = new TestingAuthenticationToken(null, "koala",
                new GrantedAuthority[] {});
        SecureContext sc = new SecureContextImpl();
        sc.setAuthentication(auth);
        ContextHolder.setContext(sc);

        authenticationTag.setOperation("principal");
        assertEquals(Tag.SKIP_BODY, authenticationTag.doStartTag());
    }

    public void testSkipsBodyIfNullOrEmptyOperation() throws Exception {
        authenticationTag.setOperation("");
        assertEquals("", authenticationTag.getOperation());
        assertEquals(Tag.SKIP_BODY, authenticationTag.doStartTag());
    }

    public void testThrowsExceptionForUnrecognisedOperation() {
        authenticationTag.setOperation("qsq");

        try {
            authenticationTag.doStartTag();
            fail("Should have throwns JspException");
        } catch (JspException expected) {
            assertTrue(true);
        }
    }

    //~ Inner Classes ==========================================================

    private class MyAuthenticationTag extends AuthenticationTag {
        String lastMessage = null;

        public String getLastMessage() {
            return lastMessage;
        }

        protected void writeMessage(String msg) throws JspException {
            lastMessage = msg;
        }
    }
}
