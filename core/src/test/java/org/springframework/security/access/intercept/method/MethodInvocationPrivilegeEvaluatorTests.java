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

package org.springframework.security.access.intercept.method;

import static org.junit.Assert.*;

import java.util.List;

import org.aopalliance.intercept.MethodInvocation;
import org.jmock.Expectations;
import org.jmock.Mockery;
import org.jmock.integration.junit4.JUnit4Mockery;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.AuthenticationManager;
import org.springframework.security.ITargetObject;
import org.springframework.security.OtherTargetObject;
import org.springframework.security.TargetObject;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.intercept.method.MethodInvocationPrivilegeEvaluator;
import org.springframework.security.access.intercept.method.MethodSecurityMetadataSource;
import org.springframework.security.access.intercept.method.aopalliance.MethodSecurityInterceptor;
import org.springframework.security.context.SecurityContextHolder;
import org.springframework.security.providers.TestingAuthenticationToken;
import org.springframework.security.util.MethodInvocationUtils;


/**
 * Tests {@link org.springframework.security.access.intercept.method.MethodInvocationPrivilegeEvaluator}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class MethodInvocationPrivilegeEvaluatorTests {
    private Mockery jmock = new JUnit4Mockery();
    private TestingAuthenticationToken token;
    private MethodSecurityInterceptor interceptor;
    private AccessDecisionManager adm;
    private MethodSecurityMetadataSource mds;
    private final List<ConfigAttribute> role = SecurityConfig.createList("ROLE_IGNORED");

    //~ Methods ========================================================================================================

    @Before
    public final void setUp() throws Exception {
        SecurityContextHolder.clearContext();
        interceptor = new MethodSecurityInterceptor();
        token = new TestingAuthenticationToken("Test", "Password", "ROLE_SOMETHING");
        adm = jmock.mock(AccessDecisionManager.class);
        AuthenticationManager authman = jmock.mock(AuthenticationManager.class);
        mds = jmock.mock(MethodSecurityMetadataSource.class);
        interceptor.setAccessDecisionManager(adm);
        interceptor.setAuthenticationManager(authman);
        interceptor.setSecurityMetadataSource(mds);
    }

    @Test
    public void allowsAccessUsingCreate() throws Exception {
        Object object = new TargetObject();
        final MethodInvocation mi = MethodInvocationUtils.create(object, "makeLowerCase", "foobar");

        MethodInvocationPrivilegeEvaluator mipe = new MethodInvocationPrivilegeEvaluator();
        jmock.checking(new Expectations() {{
            oneOf(mds).getAttributes(mi); will(returnValue(role));
            oneOf(adm).decide(token, mi, role);
        }});

        mipe.setSecurityInterceptor(interceptor);
        mipe.afterPropertiesSet();

        assertTrue(mipe.isAllowed(mi, token));
    }

    @Test
    public void allowsAccessUsingCreateFromClass() throws Exception {
        final MethodInvocation mi = MethodInvocationUtils.createFromClass(new OtherTargetObject(), ITargetObject.class, "makeLowerCase",
                new Class[] {String.class}, new Object[] {"Hello world"});
        MethodInvocationPrivilegeEvaluator mipe = new MethodInvocationPrivilegeEvaluator();
        mipe.setSecurityInterceptor(interceptor);
        jmock.checking(new Expectations() {{
            oneOf(mds).getAttributes(mi); will(returnValue(role));
            oneOf(adm).decide(token, mi, role);
        }});

        assertTrue(mipe.isAllowed(mi, token));
    }

    @Test
    public void declinesAccessUsingCreate() throws Exception {
        Object object = new TargetObject();
        final MethodInvocation mi = MethodInvocationUtils.create(object, "makeLowerCase", new Object[] {"foobar"});
        MethodInvocationPrivilegeEvaluator mipe = new MethodInvocationPrivilegeEvaluator();
        mipe.setSecurityInterceptor(interceptor);
        jmock.checking(new Expectations() {{
            oneOf(mds).getAttributes(mi); will(returnValue(role));
            oneOf(adm).decide(token, mi, role); will(throwException(new AccessDeniedException("rejected")));
        }});

        assertFalse(mipe.isAllowed(mi, token));
    }

    @Test
    public void declinesAccessUsingCreateFromClass() throws Exception {
        final MethodInvocation mi = MethodInvocationUtils.createFromClass(new OtherTargetObject(), ITargetObject.class, "makeLowerCase",
                new Class[] {String.class}, new Object[] {"helloWorld"});

        MethodInvocationPrivilegeEvaluator mipe = new MethodInvocationPrivilegeEvaluator();
        mipe.setSecurityInterceptor(interceptor);
        jmock.checking(new Expectations() {{
            oneOf(mds).getAttributes(mi); will(returnValue(role));
            oneOf(adm).decide(token, mi, role); will(throwException(new AccessDeniedException("rejected")));
        }});

        assertFalse(mipe.isAllowed(mi, token));
    }
}
