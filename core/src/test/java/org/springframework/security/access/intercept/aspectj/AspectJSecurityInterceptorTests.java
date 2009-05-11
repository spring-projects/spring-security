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

package org.springframework.security.access.intercept.aspectj;

import java.lang.reflect.Method;
import java.util.List;

import org.aspectj.lang.JoinPoint;
import org.jmock.Expectations;
import org.jmock.Mockery;
import org.jmock.integration.junit4.JUnit4Mockery;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.MockJoinPoint;
import org.springframework.security.TargetObject;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.intercept.aspectj.AspectJCallback;
import org.springframework.security.access.intercept.aspectj.AspectJSecurityInterceptor;
import org.springframework.security.access.method.MethodSecurityMetadataSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;


/**
 * Tests {@link AspectJSecurityInterceptor}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class AspectJSecurityInterceptorTests {
    private Mockery jmock = new JUnit4Mockery();
    private TestingAuthenticationToken token;
    private AspectJSecurityInterceptor interceptor;
    private AccessDecisionManager adm;
    private MethodSecurityMetadataSource mds;
    private AuthenticationManager authman;
    private AspectJCallback aspectJCallback;
    private JoinPoint joinPoint;

    //~ Methods ========================================================================================================

    @Before
    public final void setUp() throws Exception {
        SecurityContextHolder.clearContext();
        token = new TestingAuthenticationToken("Test", "Password");
        interceptor = new AspectJSecurityInterceptor();
        adm = jmock.mock(AccessDecisionManager.class);
        authman = jmock.mock(AuthenticationManager.class);
        mds = jmock.mock(MethodSecurityMetadataSource.class);
        interceptor.setAccessDecisionManager(adm);
        interceptor.setAuthenticationManager(authman);
        interceptor.setSecurityMetadataSource(mds);
        Method method = TargetObject.class.getMethod("countLength", new Class[] {String.class});
        joinPoint = new MockJoinPoint(new TargetObject(), method);
        aspectJCallback = jmock.mock(AspectJCallback.class);
    }

    @After
    public void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    @SuppressWarnings("unchecked")
    public void callbackIsInvokedWhenPermissionGranted() throws Exception {
        jmock.checking(new Expectations() {{
            oneOf(mds).getAttributes(with(any(JoinPoint.class))); will (returnValue(SecurityConfig.createList("ROLE_USER")));
            oneOf(authman).authenticate(token); will(returnValue(token));
            oneOf(adm).decide(with(token), with(aNonNull(JoinPoint.class)), with(aNonNull(List.class)));
            oneOf(aspectJCallback).proceedWithObject();
        }});

        SecurityContextHolder.getContext().setAuthentication(token);
        interceptor.invoke(joinPoint, aspectJCallback);
        jmock.assertIsSatisfied();
    }

    @SuppressWarnings("unchecked")
    @Test(expected=AccessDeniedException.class)
    public void callbackIsNotInvokedWhenPermissionDenied() throws Exception {
        jmock.checking(new Expectations() {{
            oneOf(mds).getAttributes(with(any(JoinPoint.class))); will (returnValue(SecurityConfig.createList("ROLE_USER")));
            oneOf(authman).authenticate(token); will(returnValue(token));
            oneOf(adm).decide(with(token), with(aNonNull(JoinPoint.class)), with(aNonNull(List.class)));
                will(throwException(new AccessDeniedException("denied")));
            never(aspectJCallback).proceedWithObject();
        }});

        SecurityContextHolder.getContext().setAuthentication(token);
        interceptor.invoke(joinPoint, aspectJCallback);
        jmock.assertIsSatisfied();
    }
}
