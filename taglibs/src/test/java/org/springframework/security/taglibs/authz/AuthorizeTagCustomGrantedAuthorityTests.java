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

import static org.junit.Assert.*;

import org.junit.*;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import javax.servlet.jsp.JspException;
import javax.servlet.jsp.tagext.Tag;
import java.util.*;



/**
 *
 * @author Francois Beausoleil
 */
public class AuthorizeTagCustomGrantedAuthorityTests {
    //~ Instance fields ================================================================================================

    private final JspAuthorizeTag authorizeTag = new JspAuthorizeTag();

    //~ Methods ========================================================================================================

    @Before
    public void setUp() {
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("abc", "123", "ROLE_TELLER"));
    }

    @After
    public void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    public void testAllowsRequestWhenCustomAuthorityPresentsCorrectRole() throws JspException {
        authorizeTag.setIfAnyGranted("ROLE_TELLER");
        assertEquals("authorized - ROLE_TELLER in both sets", Tag.EVAL_BODY_INCLUDE, authorizeTag.doStartTag());
    }

    @Test
    public void testRejectsRequestWhenCustomAuthorityReturnsNull() throws JspException {
        authorizeTag.setIfAnyGranted("ROLE_TELLER");
        List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
        authorities.add(new GrantedAuthority() {
                    public String getAuthority() {
                        return null;
                    }
                });
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("abc", "123", authorities));

        try {
            authorizeTag.doStartTag();
            fail("Failed to reject GrantedAuthority with NULL getAuthority()");
        } catch (IllegalArgumentException expected) {
            assertTrue("expected", true);
        }
    }
}
