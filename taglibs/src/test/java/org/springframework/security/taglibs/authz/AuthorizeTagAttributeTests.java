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


import static org.junit.Assert.assertEquals;

import org.junit.*;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import javax.servlet.jsp.JspException;
import javax.servlet.jsp.tagext.Tag;


/**
 * @author Francois Beausoleil
 */
public class AuthorizeTagAttributeTests {
    //~ Instance fields ================================================================================================

    private final JspAuthorizeTag authorizeTag = new JspAuthorizeTag();

    //~ Methods ========================================================================================================

    @Before
    public void setUp() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("abc", "123", "ROLE_SUPERVISOR", "ROLE_RESTRICTED"));
    }

    @After
    public void tearDown() throws Exception {
        SecurityContextHolder.clearContext();
    }

    @Test
    public void testAssertsIfAllGrantedSecond() throws JspException {
        authorizeTag.setIfAllGranted("ROLE_SUPERVISOR,ROLE_SUPERTELLER");
        authorizeTag.setIfAnyGranted("ROLE_RESTRICTED");
        assertEquals("prevents request - principal is missing ROLE_SUPERTELLER", Tag.SKIP_BODY,
            authorizeTag.doStartTag());
    }

    @Test
    public void testAssertsIfAnyGrantedLast() throws JspException {
        authorizeTag.setIfAnyGranted("ROLE_BANKER");
        assertEquals("prevents request - principal is missing ROLE_BANKER", Tag.SKIP_BODY, authorizeTag.doStartTag());
    }

    @Test
    public void testAssertsIfNotGrantedFirst() throws JspException {
        authorizeTag.setIfNotGranted("ROLE_RESTRICTED");
        authorizeTag.setIfAllGranted("ROLE_SUPERVISOR,ROLE_RESTRICTED");
        authorizeTag.setIfAnyGranted("ROLE_SUPERVISOR");
        assertEquals("prevents request - principal has ROLE_RESTRICTED", Tag.SKIP_BODY, authorizeTag.doStartTag());
    }

    @Test
    public void testAssertsIfNotGrantedIgnoresWhitespaceInAttribute()
        throws JspException {
        authorizeTag.setIfAnyGranted("\tROLE_SUPERVISOR  \t, \r\n\t ROLE_TELLER ");
        assertEquals("allows request - principal has ROLE_SUPERVISOR", Tag.EVAL_BODY_INCLUDE, authorizeTag.doStartTag());
    }

    @Test
    public void testIfAllGrantedIgnoresWhitespaceInAttribute() throws JspException {
        authorizeTag.setIfAllGranted("\nROLE_SUPERVISOR\t,ROLE_RESTRICTED\t\n\r ");
        assertEquals("allows request - principal has ROLE_RESTRICTED " + "and ROLE_SUPERVISOR", Tag.EVAL_BODY_INCLUDE,
            authorizeTag.doStartTag());
    }

    @Test
    public void testIfNotGrantedIgnoresWhitespaceInAttribute() throws JspException {
        authorizeTag.setIfNotGranted(" \t  ROLE_TELLER \r");
        assertEquals("allows request - principal does not have ROLE_TELLER", Tag.EVAL_BODY_INCLUDE,
            authorizeTag.doStartTag());
    }
}
