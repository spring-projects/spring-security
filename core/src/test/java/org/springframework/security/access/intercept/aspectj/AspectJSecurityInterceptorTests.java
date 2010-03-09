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

import static org.junit.Assert.fail;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;

import java.lang.reflect.Method;
import java.util.Collection;

import org.aspectj.lang.JoinPoint;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.security.MockJoinPoint;
import org.springframework.security.TargetObject;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.method.MethodSecurityMetadataSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;


/**
 * Tests {@link AspectJSecurityInterceptor}.
 *
 * @author Ben Alex
 * @author Luke Taylor
 */
@SuppressWarnings("deprecation")
public class AspectJSecurityInterceptorTests {
    private TestingAuthenticationToken token;
    private AspectJSecurityInterceptor interceptor;
    private @Mock AccessDecisionManager adm;
    private @Mock MethodSecurityMetadataSource mds;
    private @Mock AuthenticationManager authman;
    private @Mock AspectJCallback aspectJCallback;
    private JoinPoint joinPoint;

    //~ Methods ========================================================================================================

    @Before
    public final void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        SecurityContextHolder.clearContext();
        token = new TestingAuthenticationToken("Test", "Password");
        interceptor = new AspectJSecurityInterceptor();
        interceptor.setAccessDecisionManager(adm);
        interceptor.setAuthenticationManager(authman);
        interceptor.setSecurityMetadataSource(mds);
        Method method = TargetObject.class.getMethod("countLength", new Class[] {String.class});
        joinPoint = new MockJoinPoint(new TargetObject(), method);
        when(mds.getAttributes(any(JoinPoint.class))).thenReturn(SecurityConfig.createList("ROLE_USER"));
        when(authman.authenticate(token)).thenReturn(token);
    }

    @After
    public void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    public void callbackIsInvokedWhenPermissionGranted() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(token);
        interceptor.invoke(joinPoint, aspectJCallback);
        verify(aspectJCallback).proceedWithObject();
    }

    @SuppressWarnings("unchecked")
    @Test
    public void callbackIsNotInvokedWhenPermissionDenied() throws Exception {
        doThrow(new AccessDeniedException("denied")).when(adm).decide(any(Authentication.class), any(), any(Collection.class));

        SecurityContextHolder.getContext().setAuthentication(token);
        try {
            interceptor.invoke(joinPoint, aspectJCallback);
            fail("Expected AccessDeniedException");
        } catch (AccessDeniedException expected) {
        }
        verify(aspectJCallback, never()).proceedWithObject();
    }
}
