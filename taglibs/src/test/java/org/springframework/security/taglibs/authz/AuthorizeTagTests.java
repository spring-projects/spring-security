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

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import javax.servlet.jsp.JspException;
import javax.servlet.jsp.tagext.Tag;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.MutablePropertyValues;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockPageContext;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.access.WebInvocationPrivilegeEvaluator;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.support.StaticWebApplicationContext;


/**
 * @author Francois Beausoleil
 * @author Luke Taylor
 */
public class AuthorizeTagTests {
    //~ Instance fields ================================================================================================

    private JspAuthorizeTag authorizeTag;
    private MockHttpServletRequest request = new MockHttpServletRequest();
    private final TestingAuthenticationToken currentUser = new TestingAuthenticationToken("abc", "123", "ROLE SUPERVISOR", "ROLE_TELLER");

    //~ Methods ========================================================================================================

    @Before
    public void setUp() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(currentUser);
        StaticWebApplicationContext ctx = new StaticWebApplicationContext();
        ctx.registerSingleton("expressionHandler", DefaultWebSecurityExpressionHandler.class);
        ctx.registerSingleton("wipe1", MockWebInvocationPrivilegeEvaluator.class,
                createPropertyValuesOfMockWipe("/something", "/notallowed"));
        ctx.registerSingleton("wipe2", MockWebInvocationPrivilegeEvaluator.class,
                createPropertyValuesOfMockWipe("/deniedMiddle"));
        ctx.registerSingleton("wipe3", MockWebInvocationPrivilegeEvaluator.class,
                createPropertyValuesOfMockWipe("/deniedLast"));
        MockServletContext servletCtx = new MockServletContext();
        servletCtx.setAttribute(WebApplicationContext.ROOT_WEB_APPLICATION_CONTEXT_ATTRIBUTE, ctx);
        authorizeTag = new JspAuthorizeTag();
        authorizeTag.setPageContext(new MockPageContext(servletCtx, request, new MockHttpServletResponse()));
    }

    private MutablePropertyValues createPropertyValuesOfMockWipe(String... deniedUris) {
        return new MutablePropertyValues(Collections.singletonMap("deniedUris",
                new HashSet<String>(Arrays.asList(deniedUris))));
    }

    @After
    public void tearDown() throws Exception {
        SecurityContextHolder.clearContext();
        request.removeAttribute(WebAttributes.WEB_INVOCATION_PRIVILEGE_EVALUATOR_ATTRIBUTE);
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

    @Test
    public void requestAttributeIsResolvedAsElVariable() throws JspException {
        request.setAttribute("blah", "blah");
        authorizeTag.setAccess("#blah == 'blah'");
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
    public void skipsBodyIfUrlIsNotAllowedMatchesWithFirst() throws Exception {
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

    // SEC-2189
    @Test
    public void skipsBodyIfMethodIsNotAllowedMatchesWithMiddle() throws Exception {
        authorizeTag.setUrl("/deniedMiddle");
        assertEquals(Tag.SKIP_BODY, authorizeTag.doStartTag());
    }

    // SEC-2189
    @Test
    public void skipsBodyIfMethodIsNotAllowedMatchesWithLast() throws Exception {
        authorizeTag.setUrl("/deniedLast");
        assertEquals(Tag.SKIP_BODY, authorizeTag.doStartTag());
    }

    // SEC-2189
    @Test
    public void skipsBodyIfMethodIsNotAllowedMatchesWithRequest() throws Exception {
        MockWebInvocationPrivilegeEvaluator wipe = new MockWebInvocationPrivilegeEvaluator();
        wipe.setDeniedUris(Collections.singleton("/deniedRequest"));
        request.setAttribute(WebAttributes.WEB_INVOCATION_PRIVILEGE_EVALUATOR_ATTRIBUTE, wipe);

        authorizeTag.setUrl("/deniedRequest");
        assertEquals(Tag.SKIP_BODY, authorizeTag.doStartTag());
    }

    // SEC-2189
    @Test
    public void evaluatesBodyIfUrlIsAllowedMatchesWithRequest() throws Exception {
        authorizeTag.setUrl("/allowed");
        assertEquals(Tag.EVAL_BODY_INCLUDE, authorizeTag.doStartTag());
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
        assertEquals(null, authorizeTag.getIfAllGranted());
        assertEquals(null, authorizeTag.getIfAnyGranted());
        assertEquals(null, authorizeTag.getIfNotGranted());

        assertEquals(Tag.SKIP_BODY, authorizeTag.doStartTag());
    }

    @Test
    public void testDefaultsToNotOutputtingBodyWhenNoAuthoritiesProvided() throws JspException {
        authorizeTag.setIfAllGranted("");
        authorizeTag.setIfAnyGranted("");
        authorizeTag.setIfNotGranted("");

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
        assertEquals(Tag.EVAL_BODY_INCLUDE, authorizeTag.doStartTag());
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

        private Set<String> deniedUris;

        public void setDeniedUris(Set<String> deniedUris){
            this.deniedUris = deniedUris;
        }

        public boolean isAllowed(String uri, Authentication authentication) {
            return !deniedUris.contains(uri);
        }

        public boolean isAllowed(String contextPath, String uri, String method, Authentication authentication) {
            return !deniedUris.contains(uri) && (method == null || "GET".equals(method));
        }
    }

}
