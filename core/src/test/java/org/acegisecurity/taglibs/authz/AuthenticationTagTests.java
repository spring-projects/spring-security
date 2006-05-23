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

package org.acegisecurity.taglibs.authz;

import junit.framework.TestCase;

import org.acegisecurity.Authentication;
import org.acegisecurity.GrantedAuthority;

import org.acegisecurity.context.SecurityContextHolder;

import org.acegisecurity.providers.TestingAuthenticationToken;

import org.acegisecurity.userdetails.User;

import javax.servlet.jsp.JspException;
import javax.servlet.jsp.tagext.Tag;


/**
 * Tests {@link AuthenticationTag}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class AuthenticationTagTests extends TestCase {
    //~ Instance fields ================================================================================================

    private final MyAuthenticationTag authenticationTag = new MyAuthenticationTag();

    //~ Methods ========================================================================================================

    public void testOperationAndMethodPrefixWhenPrincipalIsAUserDetailsInstance()
        throws JspException {
        Authentication auth = new TestingAuthenticationToken(new User("marissaUserDetails", "koala", true, true, true,
                    true, new GrantedAuthority[] {}), "koala", new GrantedAuthority[] {});
        SecurityContextHolder.getContext().setAuthentication(auth);

        authenticationTag.setOperation("username");
        authenticationTag.setMethodPrefix("get");
        assertEquals(Tag.SKIP_BODY, authenticationTag.doStartTag());
        assertEquals("marissaUserDetails", authenticationTag.getLastMessage());
    }

    public void testOperationWhenPrincipalIsAString() throws JspException {
        Authentication auth = new TestingAuthenticationToken("marissaAsString", "koala", new GrantedAuthority[] {});
        SecurityContextHolder.getContext().setAuthentication(auth);

        authenticationTag.setOperation("principal");
        assertEquals(Tag.SKIP_BODY, authenticationTag.doStartTag());
        assertEquals("marissaAsString", authenticationTag.getLastMessage());
    }

    public void testOperationWhenPrincipalIsAUserDetailsInstance()
        throws JspException {
        Authentication auth = new TestingAuthenticationToken(new User("marissaUserDetails", "koala", true, true, true,
                    true, new GrantedAuthority[] {}), "koala", new GrantedAuthority[] {});
        SecurityContextHolder.getContext().setAuthentication(auth);

        authenticationTag.setOperation("username");
        assertEquals(Tag.SKIP_BODY, authenticationTag.doStartTag());
        assertEquals("marissaUserDetails", authenticationTag.getLastMessage());
    }

    public void testOperationWhenPrincipalIsNull() throws JspException {
        Authentication auth = new TestingAuthenticationToken(null, "koala", new GrantedAuthority[] {});
        SecurityContextHolder.getContext().setAuthentication(auth);

        authenticationTag.setOperation("principal");
        assertEquals(Tag.SKIP_BODY, authenticationTag.doStartTag());
    }

    public void testOperationWhenSecurityContextIsNull()
        throws JspException {
        SecurityContextHolder.getContext().setAuthentication(null);

        authenticationTag.setOperation("principal");
        assertEquals(Tag.SKIP_BODY, authenticationTag.doStartTag());
        assertEquals(null, authenticationTag.getLastMessage());

        SecurityContextHolder.getContext().setAuthentication(null);
    }

    public void testSkipsBodyIfNullOrEmptyOperation() throws Exception {
        authenticationTag.setOperation("");
        assertEquals("", authenticationTag.getOperation());
        assertEquals(Tag.SKIP_BODY, authenticationTag.doStartTag());
    }

    public void testThrowsExceptionForUnrecognisedMethodPrefix() {
        Authentication auth = new TestingAuthenticationToken(new User("marissaUserDetails", "koala", true, true, true,
                    true, new GrantedAuthority[] {}), "koala", new GrantedAuthority[] {});
        SecurityContextHolder.getContext().setAuthentication(auth);
        authenticationTag.setOperation("username");
        authenticationTag.setMethodPrefix("qrq");

        try {
            authenticationTag.doStartTag();
            fail("Should have thrown a JspException");
        } catch (JspException expected) {
            assertTrue(true);
        }
    }

    public void testThrowsExceptionForUnrecognisedOperation() {
        Authentication auth = new TestingAuthenticationToken(new User("marissaUserDetails", "koala", true, true, true,
                    true, new GrantedAuthority[] {}), "koala", new GrantedAuthority[] {});
        SecurityContextHolder.getContext().setAuthentication(auth);
        authenticationTag.setOperation("qsq");

        try {
            authenticationTag.doStartTag();
            fail("Should have throwns JspException");
        } catch (JspException expected) {
            assertTrue(true);
        }
    }

    //~ Inner Classes ==================================================================================================

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
