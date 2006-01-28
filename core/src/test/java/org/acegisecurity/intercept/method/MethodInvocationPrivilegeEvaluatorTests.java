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

package org.acegisecurity.intercept.method;

import junit.framework.TestCase;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;
import org.acegisecurity.ITargetObject;

import org.acegisecurity.intercept.method.aopalliance.MethodSecurityInterceptor;

import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;

import org.acegisecurity.util.MethodInvocationUtils;

import org.aopalliance.intercept.MethodInvocation;

import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;


/**
 * Tests {@link
 * org.acegisecurity.intercept.method.MethodInvocationPrivilegeEvaluator}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class MethodInvocationPrivilegeEvaluatorTests extends TestCase {
    //~ Constructors ===========================================================

    public MethodInvocationPrivilegeEvaluatorTests() {
        super();
    }

    public MethodInvocationPrivilegeEvaluatorTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    private Object lookupTargetObject() {
        ApplicationContext context = new ClassPathXmlApplicationContext(
                "org/acegisecurity/intercept/method/aopalliance/applicationContext.xml");

        return context.getBean("target");
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(MethodInvocationPrivilegeEvaluatorTests.class);
    }

    private MethodSecurityInterceptor makeSecurityInterceptor() {
        ApplicationContext context = new ClassPathXmlApplicationContext(
                "org/acegisecurity/intercept/method/aopalliance/applicationContext.xml");

        return (MethodSecurityInterceptor) context.getBean(
            "securityInterceptor");
    }

    public void testAllowsAccessUsingCreate() throws Exception {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("Test",
                "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("MOCK_LOWER")});
        Object object = lookupTargetObject();
        MethodInvocation mi = MethodInvocationUtils.create(object,
                "makeLowerCase", new Object[] {"foobar"});
        MethodSecurityInterceptor interceptor = makeSecurityInterceptor();

        MethodInvocationPrivilegeEvaluator mipe = new MethodInvocationPrivilegeEvaluator();
        mipe.setSecurityInterceptor(interceptor);
        mipe.afterPropertiesSet();

        assertTrue(mipe.isAllowed(mi, token));
    }

    public void testAllowsAccessUsingCreateFromClass()
        throws Exception {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("Test",
                "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("MOCK_LOWER")});
        MethodInvocation mi = MethodInvocationUtils.createFromClass(ITargetObject.class,
                "makeLowerCase", new Class[] {String.class});
        MethodSecurityInterceptor interceptor = makeSecurityInterceptor();

        MethodInvocationPrivilegeEvaluator mipe = new MethodInvocationPrivilegeEvaluator();
        mipe.setSecurityInterceptor(interceptor);
        mipe.afterPropertiesSet();

        assertTrue(mipe.isAllowed(mi, token));
    }

    public void testDeclinesAccessUsingCreate() throws Exception {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("Test",
                "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_NOT_HELD")});
        Object object = lookupTargetObject();
        MethodInvocation mi = MethodInvocationUtils.create(object,
                "makeLowerCase", new Object[] {"foobar"});
        MethodSecurityInterceptor interceptor = makeSecurityInterceptor();

        MethodInvocationPrivilegeEvaluator mipe = new MethodInvocationPrivilegeEvaluator();
        mipe.setSecurityInterceptor(interceptor);
        mipe.afterPropertiesSet();

        assertFalse(mipe.isAllowed(mi, token));
    }

    public void testDeclinesAccessUsingCreateFromClass()
        throws Exception {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("Test",
                "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_NOT_HELD")});
        MethodInvocation mi = MethodInvocationUtils.createFromClass(ITargetObject.class,
                "makeLowerCase", new Class[] {String.class});
        MethodSecurityInterceptor interceptor = makeSecurityInterceptor();

        MethodInvocationPrivilegeEvaluator mipe = new MethodInvocationPrivilegeEvaluator();
        mipe.setSecurityInterceptor(interceptor);
        mipe.afterPropertiesSet();

        assertFalse(mipe.isAllowed(mi, token));
    }
}
