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

import javax.servlet.jsp.JspException;
import javax.servlet.jsp.el.VariableResolver;
import javax.servlet.jsp.tagext.Tag;

import junit.framework.TestCase;

import org.jmock.Mockery;
import org.springframework.mock.web.MockPageContext;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.GrantedAuthorityImpl;
import org.springframework.security.core.context.SecurityContextHolder;


/**
 * Test case to implement commons-el expression language expansion.
 */
public class AuthorizeTagExpressionLanguageTests extends TestCase {
    Mockery jmock = new Mockery();
    //~ Instance fields ================================================================================================

    private final AuthorizeTag authorizeTag = new AuthorizeTag();
    private MockPageContext pageContext;
    private TestingAuthenticationToken currentUser;

    //~ Methods ========================================================================================================

    protected void setUp() throws Exception {
        pageContext = new MockPageContext() {
            public VariableResolver getVariableResolver() {
                return null;
            }
        };
        authorizeTag.setPageContext(pageContext);

        currentUser = new TestingAuthenticationToken("abc", "123",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_TELLER"),});

        SecurityContextHolder.getContext().setAuthentication(currentUser);
    }

    protected void tearDown() throws Exception {
        SecurityContextHolder.clearContext();
    }

    public void testAllGrantedUsesExpressionLanguageWhenExpressionIsEL() throws JspException {
        pageContext.setAttribute("authority", "ROLE_TELLER");
        authorizeTag.setIfAllGranted("${authority}");

        assertEquals("allows body - authority var contains ROLE_TELLER", Tag.EVAL_BODY_INCLUDE,
            authorizeTag.doStartTag());
    }

    public void testAnyGrantedUsesExpressionLanguageWhenExpressionIsEL() throws JspException {
        pageContext.setAttribute("authority", "ROLE_TELLER");
        authorizeTag.setIfAnyGranted("${authority}");

        assertEquals("allows body - authority var contains ROLE_TELLER", Tag.EVAL_BODY_INCLUDE,
            authorizeTag.doStartTag());
    }

    public void testNotGrantedUsesExpressionLanguageWhenExpressionIsEL() throws JspException {
        pageContext.setAttribute("authority", "ROLE_TELLER");
        authorizeTag.setIfNotGranted("${authority}");

        assertEquals("allows body - authority var contains ROLE_TELLER", Tag.SKIP_BODY, authorizeTag.doStartTag());
    }
}
