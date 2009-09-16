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

import javax.servlet.jsp.JspException;
import javax.servlet.jsp.tagext.Tag;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockPageContext;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.access.WebInvocationPrivilegeEvaluator;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.support.StaticWebApplicationContext;


/**
 * @author Francois Beausoleil
 * @author Luke Taylor
 * @version $Id$
 */
public class AuthorizeTagTests {
    //~ Instance fields ================================================================================================

    private AuthorizeTag authorizeTag;
    private final TestingAuthenticationToken currentUser = new TestingAuthenticationToken("abc", "123", "ROLE SUPERVISOR", "ROLE_TELLER");

    //~ Methods ========================================================================================================

    @Before
    public void setUp() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(currentUser);
        StaticWebApplicationContext ctx = new StaticWebApplicationContext();
        ctx.registerSingleton("expressionHandler", DefaultWebSecurityExpressionHandler.class);
        ctx.registerSingleton("wipe", MockWebInvocationPrivilegeEvaluator.class);
        MockServletContext servletCtx = new MockServletContext();
        servletCtx.setAttribute(WebApplicationContext.ROOT_WEB_APPLICATION_CONTEXT_ATTRIBUTE, ctx);
        authorizeTag = new AuthorizeTag();
        authorizeTag.setPageContext(new MockPageContext(servletCtx, new MockHttpServletRequest(), new MockHttpServletResponse()));
    }

    @After
    public void tearDown() throws Exception {
        SecurityContextHolder.clearContext();
    }

    // access attribute tests

    @Test
    public void skipsBodyIfNoAuthenticationPresent() throws Exception {
        SecurityContextHolder.clearContext();
        authorizeTag.setAccess("permitAll");
        assertEquals(Tag.SKIP_BODY, authorizeTag.doStartTag());
    }

    @Test
    public void skipsBodyIfAccessExpressionDeniesAccess() throws Exception {
        authorizeTag.setAccess("denyAll");
        assertEquals(Tag.SKIP_BODY, authorizeTag.doStartTag());
    }

    @Test
    public void showsBodyIfAccessExpressionAllowsAccess() throws Exception {
        authorizeTag.setAccess("permitAll");
        assertEquals(Tag.EVAL_BODY_INCLUDE, authorizeTag.doStartTag());
    }

    // url attribute tests
    @Test
    public void skipsBodyWithUrlSetIfNoAuthenticationPresent() throws Exception {
        SecurityContextHolder.clearContext();
        authorizeTag.setUrl("/something");
        assertEquals(Tag.SKIP_BODY, authorizeTag.doStartTag());
    }

    @Test
    public void skipsBodyIfUrlIsNotAllowed() throws Exception {
        authorizeTag.setUrl("/notallowed");
        assertEquals(Tag.SKIP_BODY, authorizeTag.doStartTag());
    }

    @Test
    public void evaluatesBodyIfUrlIsAllowed() throws Exception {
        authorizeTag.setUrl("/allowed");
        authorizeTag.setMethod("GET");
        assertEquals(Tag.EVAL_BODY_INCLUDE, authorizeTag.doStartTag());
    }

    @Test
    public void skipsBodyIfMethodIsNotAllowed() throws Exception {
        authorizeTag.setUrl("/allowed");
        authorizeTag.setMethod("POST");
        assertEquals(Tag.SKIP_BODY, authorizeTag.doStartTag());
    }

    // Legacy attribute tests

    @Test
    public void testAlwaysReturnsUnauthorizedIfNoUserFound() throws JspException {
        SecurityContextHolder.clearContext();
        authorizeTag.setIfAllGranted("ROLE_TELLER");
        assertEquals(Tag.SKIP_BODY, authorizeTag.doStartTag());
    }

    @Test
    public void testDefaultsToNotOutputtingBodyWhenNoRequiredAuthorities() throws JspException {
        assertEquals("", authorizeTag.getIfAllGranted());
        assertEquals("", authorizeTag.getIfAnyGranted());
        assertEquals("", authorizeTag.getIfNotGranted());

        assertEquals(Tag.SKIP_BODY, authorizeTag.doStartTag());
    }

    @Test
    public void testOutputsBodyIfOneRolePresent() throws JspException {
        authorizeTag.setIfAnyGranted("ROLE_TELLER");
        assertEquals(Tag.EVAL_BODY_INCLUDE, authorizeTag.doStartTag());
    }

    @Test
    public void testOutputsBodyWhenAllGranted() throws JspException {
        authorizeTag.setIfAllGranted("ROLE SUPERVISOR, \nROLE_TELLER");
        assertEquals(Tag.EVAL_BODY_INCLUDE, authorizeTag.doStartTag());
    }

    @Test
    public void testOutputsBodyWhenNotGrantedSatisfied() throws JspException {
        authorizeTag.setIfNotGranted("ROLE_BANKER");
        assertEquals(Tag.EVAL_BODY_INCLUDE,
            authorizeTag.doStartTag());
    }

    @Test
    public void testPreventsBodyOutputIfNoSecurityContext() throws JspException {
        SecurityContextHolder.getContext().setAuthentication(null);
        authorizeTag.setIfAnyGranted("ROLE_BANKER");

        assertEquals(Tag.SKIP_BODY, authorizeTag.doStartTag());
    }

    @Test
    public void testSkipsBodyIfNoAnyRolePresent() throws JspException {
        authorizeTag.setIfAnyGranted("ROLE_BANKER");
        assertEquals(Tag.SKIP_BODY, authorizeTag.doStartTag());
    }

    @Test
    public void testSkipsBodyWhenMissingAnAllGranted() throws JspException {
        authorizeTag.setIfAllGranted("ROLE SUPERVISOR, ROLE_TELLER,\n\rROLE_BANKER");
        assertEquals(Tag.SKIP_BODY, authorizeTag.doStartTag());
    }

    @Test
    public void testSkipsBodyWhenNotGrantedUnsatisfied() throws JspException {
        authorizeTag.setIfNotGranted("ROLE_TELLER");
        assertEquals("prevents request - principal has ROLE_TELLER", Tag.SKIP_BODY, authorizeTag.doStartTag());
    }

    public static class MockWebInvocationPrivilegeEvaluator implements WebInvocationPrivilegeEvaluator {

        public boolean isAllowed(String uri, Authentication authentication) {
            return "/allowed".equals(uri);
        }

        public boolean isAllowed(String contextPath, String uri, String method, Authentication authentication) {
            return "/allowed".equals(uri) && (method == null || "GET".equals(method));
        }
    }
}
