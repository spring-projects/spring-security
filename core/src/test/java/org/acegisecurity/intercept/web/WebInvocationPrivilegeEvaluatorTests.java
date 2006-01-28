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

package org.acegisecurity.intercept.web;

import junit.framework.TestCase;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;

import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;

import org.acegisecurity.util.FilterInvocationUtils;

import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;


/**
 * Tests {@link
 * org.acegisecurity.intercept.web.WebInvocationPrivilegeEvaluator}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class WebInvocationPrivilegeEvaluatorTests extends TestCase {
    //~ Constructors ===========================================================

    public WebInvocationPrivilegeEvaluatorTests() {
        super();
    }

    public WebInvocationPrivilegeEvaluatorTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public static void main(String[] args) {
        junit.textui.TestRunner.run(WebInvocationPrivilegeEvaluatorTests.class);
    }

    private FilterSecurityInterceptor makeFilterSecurityInterceptor() {
        ApplicationContext context = new ClassPathXmlApplicationContext(
                "org/acegisecurity/intercept/web/applicationContext.xml");

        return (FilterSecurityInterceptor) context.getBean(
            "securityInterceptor");
    }

    public void testAllowsAccess1() throws Exception {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("Test",
                "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("MOCK_INDEX")});
        FilterInvocation fi = FilterInvocationUtils.create("/foo/index.jsp");
        FilterSecurityInterceptor interceptor = makeFilterSecurityInterceptor();

        WebInvocationPrivilegeEvaluator wipe = new WebInvocationPrivilegeEvaluator();
        wipe.setSecurityInterceptor(interceptor);
        wipe.afterPropertiesSet();

        assertTrue(wipe.isAllowed(fi, token));
    }

    public void testAllowsAccess2() throws Exception {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("Test",
                "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("MOCK_USER")});
        FilterInvocation fi = FilterInvocationUtils.create("/anything.jsp");
        FilterSecurityInterceptor interceptor = makeFilterSecurityInterceptor();

        WebInvocationPrivilegeEvaluator wipe = new WebInvocationPrivilegeEvaluator();
        wipe.setSecurityInterceptor(interceptor);
        wipe.afterPropertiesSet();

        assertTrue(wipe.isAllowed(fi, token));
    }

    public void testDeniesAccess1() throws Exception {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("Test",
                "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("MOCK_NOTHING_USEFUL")});
        FilterInvocation fi = FilterInvocationUtils.create("/anything.jsp");
        FilterSecurityInterceptor interceptor = makeFilterSecurityInterceptor();

        WebInvocationPrivilegeEvaluator wipe = new WebInvocationPrivilegeEvaluator();
        wipe.setSecurityInterceptor(interceptor);
        wipe.afterPropertiesSet();

        assertFalse(wipe.isAllowed(fi, token));
    }
}
