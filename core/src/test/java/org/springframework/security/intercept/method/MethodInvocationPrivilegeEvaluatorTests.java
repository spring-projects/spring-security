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

package org.springframework.security.intercept.method;

import static org.junit.Assert.*;

import org.aopalliance.intercept.MethodInvocation;
import org.junit.Test;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.security.ITargetObject;
import org.springframework.security.OtherTargetObject;
import org.springframework.security.intercept.method.aopalliance.MethodSecurityInterceptor;
import org.springframework.security.providers.UsernamePasswordAuthenticationToken;
import org.springframework.security.util.AuthorityUtils;
import org.springframework.security.util.MethodInvocationUtils;


/**
 * Tests {@link org.springframework.security.intercept.method.MethodInvocationPrivilegeEvaluator}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class MethodInvocationPrivilegeEvaluatorTests {

    //~ Methods ========================================================================================================

    private Object lookupTargetObject() {
        ApplicationContext context = new ClassPathXmlApplicationContext(
                "org/springframework/security/intercept/method/aopalliance/applicationContext.xml");

        return context.getBean("target");
    }

    private MethodSecurityInterceptor makeSecurityInterceptor() {
        ApplicationContext context = new ClassPathXmlApplicationContext(
                "org/springframework/security/intercept/method/aopalliance/applicationContext.xml");

        return (MethodSecurityInterceptor) context.getBean("securityInterceptor");
    }

    @Test
    public void allowsAccessUsingCreate() throws Exception {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("Test", "Password",
                AuthorityUtils.createAuthorityList("MOCK_LOWER"));
        Object object = lookupTargetObject();
        MethodInvocation mi = MethodInvocationUtils.create(object, "makeLowerCase", "foobar");
        MethodSecurityInterceptor interceptor = makeSecurityInterceptor();

        MethodInvocationPrivilegeEvaluator mipe = new MethodInvocationPrivilegeEvaluator();
        mipe.setSecurityInterceptor(interceptor);
        mipe.afterPropertiesSet();

        assertTrue(mipe.isAllowed(mi, token));
    }

    @Test
    public void allowsAccessUsingCreateFromClass() throws Exception {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("Test", "Password",
                AuthorityUtils.createAuthorityList("MOCK_LOWER"));
        MethodInvocation mi = MethodInvocationUtils.createFromClass(new OtherTargetObject(), ITargetObject.class, "makeLowerCase",
                new Class[] {String.class}, new Object[] {"Hello world"});
        MethodSecurityInterceptor interceptor = makeSecurityInterceptor();

        MethodInvocationPrivilegeEvaluator mipe = new MethodInvocationPrivilegeEvaluator();
        mipe.setSecurityInterceptor(interceptor);
        mipe.afterPropertiesSet();

        assertTrue(mipe.isAllowed(mi, token));
    }

    @Test
    public void declinesAccessUsingCreate() throws Exception {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("Test", "Password",
                AuthorityUtils.createAuthorityList("ROLE_NOT_HELD"));
        Object object = lookupTargetObject();
        MethodInvocation mi = MethodInvocationUtils.create(object, "makeLowerCase", new Object[] {"foobar"});
        MethodSecurityInterceptor interceptor = makeSecurityInterceptor();

        MethodInvocationPrivilegeEvaluator mipe = new MethodInvocationPrivilegeEvaluator();
        mipe.setSecurityInterceptor(interceptor);
        mipe.afterPropertiesSet();

        assertFalse(mipe.isAllowed(mi, token));
    }

    @Test
    public void declinesAccessUsingCreateFromClass() throws Exception {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("Test", "Password",
                AuthorityUtils.createAuthorityList("ROLE_NOT_HELD"));
        MethodInvocation mi = MethodInvocationUtils.createFromClass(new OtherTargetObject(), ITargetObject.class, "makeLowerCase",
                new Class[] {String.class}, new Object[] {"helloWorld"});
        MethodSecurityInterceptor interceptor = makeSecurityInterceptor();

        MethodInvocationPrivilegeEvaluator mipe = new MethodInvocationPrivilegeEvaluator();
        mipe.setSecurityInterceptor(interceptor);
        mipe.afterPropertiesSet();

        assertFalse(mipe.isAllowed(mi, token));
    }
}
