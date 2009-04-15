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

import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;

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
    private final Authentication auth = new TestingAuthenticationToken(new User("rodUserDetails", "koala", true, true, true,
                    true, AuthorityUtils.NO_AUTHORITIES), "koala", AuthorityUtils.NO_AUTHORITIES);

    //~ Methods ========================================================================================================

    protected void tearDown() throws Exception {
        SecurityContextHolder.clearContext();
    }

    public void testOperationWhenPrincipalIsAUserDetailsInstance()throws JspException {
        SecurityContextHolder.getContext().setAuthentication(auth);

        authenticationTag.setProperty("name");
        assertEquals(Tag.SKIP_BODY, authenticationTag.doStartTag());
        assertEquals(Tag.EVAL_PAGE, authenticationTag.doEndTag());
        assertEquals("rodUserDetails", authenticationTag.getLastMessage());
    }

    public void testOperationWhenPrincipalIsAString() throws JspException {
        SecurityContextHolder.getContext().setAuthentication(
                new TestingAuthenticationToken("rodAsString", "koala", AuthorityUtils.NO_AUTHORITIES ));

        authenticationTag.setProperty("principal");
        assertEquals(Tag.SKIP_BODY, authenticationTag.doStartTag());
        assertEquals(Tag.EVAL_PAGE, authenticationTag.doEndTag());
        assertEquals("rodAsString", authenticationTag.getLastMessage());
    }

    public void testNestedPropertyIsReadCorrectly() throws JspException {
        SecurityContextHolder.getContext().setAuthentication(auth);

        authenticationTag.setProperty("principal.username");
        assertEquals(Tag.SKIP_BODY, authenticationTag.doStartTag());
        assertEquals(Tag.EVAL_PAGE, authenticationTag.doEndTag());
        assertEquals("rodUserDetails", authenticationTag.getLastMessage());
    }

    public void testOperationWhenPrincipalIsNull() throws JspException {
        SecurityContextHolder.getContext().setAuthentication(
                new TestingAuthenticationToken(null, "koala", AuthorityUtils.NO_AUTHORITIES ));

        authenticationTag.setProperty("principal");
        assertEquals(Tag.SKIP_BODY, authenticationTag.doStartTag());
        assertEquals(Tag.EVAL_PAGE, authenticationTag.doEndTag());
    }

    public void testOperationWhenSecurityContextIsNull() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(null);

        authenticationTag.setProperty("principal");
        assertEquals(Tag.SKIP_BODY, authenticationTag.doStartTag());
        assertEquals(Tag.EVAL_PAGE, authenticationTag.doEndTag());
        assertEquals(null, authenticationTag.getLastMessage());
    }

    public void testSkipsBodyIfNullOrEmptyOperation() throws Exception {
        authenticationTag.setProperty("");
        assertEquals(Tag.SKIP_BODY, authenticationTag.doStartTag());
        assertEquals(Tag.EVAL_PAGE, authenticationTag.doEndTag());
    }

    public void testThrowsExceptionForUnrecognisedProperty() {
        SecurityContextHolder.getContext().setAuthentication(auth);
        authenticationTag.setProperty("qsq");

        try {
            authenticationTag.doStartTag();
            authenticationTag.doEndTag();
            fail("Should have throwns JspException");
        } catch (JspException expected) {
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
