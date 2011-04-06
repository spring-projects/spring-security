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

package org.springframework.security.access.intercept.aopalliance;

import static org.junit.Assert.*;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;

import java.util.*;

import org.aopalliance.intercept.MethodInvocation;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.aop.framework.ProxyFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.ITargetObject;
import org.springframework.security.TargetObject;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.event.AuthorizationFailureEvent;
import org.springframework.security.access.event.AuthorizedEvent;
import org.springframework.security.access.intercept.AfterInvocationManager;
import org.springframework.security.access.intercept.RunAsManager;
import org.springframework.security.access.intercept.RunAsUserToken;
import org.springframework.security.access.method.MethodSecurityMetadataSource;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Tests {@link MethodSecurityInterceptor}.
 *
 * @author Ben Alex
 */
@SuppressWarnings("unchecked")
public class MethodSecurityInterceptorTests {
    private TestingAuthenticationToken token;
    private MethodSecurityInterceptor interceptor;
    private ITargetObject realTarget;
    private ITargetObject advisedTarget;
    private AccessDecisionManager adm;
    private MethodSecurityMetadataSource mds;
    private AuthenticationManager authman;
    private ApplicationEventPublisher eventPublisher;

    //~ Methods ========================================================================================================

    @Before
    public final void setUp() throws Exception {
        SecurityContextHolder.clearContext();
        token = new TestingAuthenticationToken("Test", "Password");
        interceptor = new MethodSecurityInterceptor();
        adm = mock(AccessDecisionManager.class);
        authman = mock(AuthenticationManager.class);
        mds = mock(MethodSecurityMetadataSource.class);
        eventPublisher = mock(ApplicationEventPublisher.class);
        interceptor.setAccessDecisionManager(adm);
        interceptor.setAuthenticationManager(authman);
        interceptor.setSecurityMetadataSource(mds);
        interceptor.setApplicationEventPublisher(eventPublisher);
        createTarget(false);
    }

    @After
    public void tearDown() throws Exception {
        SecurityContextHolder.clearContext();
    }

    private void createTarget(boolean useMock) {
        realTarget = useMock ? mock(ITargetObject.class) : new TargetObject();
        ProxyFactory pf = new ProxyFactory(realTarget);
        pf.addAdvice(interceptor);
        advisedTarget = (ITargetObject) pf.getProxy();
    }

    @Test
    public void gettersReturnExpectedData() {
        RunAsManager runAs = mock(RunAsManager.class);
        AfterInvocationManager aim = mock(AfterInvocationManager.class);
        interceptor.setRunAsManager(runAs);
        interceptor.setAfterInvocationManager(aim);
        assertEquals(adm, interceptor.getAccessDecisionManager());
        assertEquals(runAs, interceptor.getRunAsManager());
        assertEquals(authman, interceptor.getAuthenticationManager());
        assertEquals(mds, interceptor.getSecurityMetadataSource());
        assertEquals(aim, interceptor.getAfterInvocationManager());
    }

    @Test(expected=IllegalArgumentException.class)
    public void missingAccessDecisionManagerIsDetected() throws Exception {
        interceptor.setAccessDecisionManager(null);
        interceptor.afterPropertiesSet();
    }

    @Test(expected=IllegalArgumentException.class)
    public void missingAuthenticationManagerIsDetected() throws Exception {
        interceptor.setAuthenticationManager(null);
        interceptor.afterPropertiesSet();
    }

    @Test(expected=IllegalArgumentException.class)
    public void missingMethodSecurityMetadataSourceIsRejected() throws Exception {
        interceptor.setSecurityMetadataSource(null);
        interceptor.afterPropertiesSet();
    }

    @Test(expected=IllegalArgumentException.class)
    public void missingRunAsManagerIsRejected() throws Exception {
        interceptor.setRunAsManager(null);
        interceptor.afterPropertiesSet();
    }

    @Test(expected=IllegalArgumentException.class)
    public void initializationRejectsSecurityMetadataSourceThatDoesNotSupportMethodInvocation() throws Throwable {
        when(mds.supports(MethodInvocation.class)).thenReturn(false);
        interceptor.afterPropertiesSet();
    }

    @Test(expected=IllegalArgumentException.class)
    public void initializationRejectsAccessDecisionManagerThatDoesNotSupportMethodInvocation() throws Exception {
        when(mds.supports(MethodInvocation.class)).thenReturn(true);
        when(adm.supports(MethodInvocation.class)).thenReturn(false);
        interceptor.afterPropertiesSet();
    }

    @Test(expected=IllegalArgumentException.class)
    public void intitalizationRejectsRunAsManagerThatDoesNotSupportMethodInvocation() throws Exception {
        final RunAsManager ram = mock(RunAsManager.class);
        when(ram.supports(MethodInvocation.class)).thenReturn(false);
        interceptor.setRunAsManager(ram);
        interceptor.afterPropertiesSet();
    }

    @Test(expected=IllegalArgumentException.class)
    public void intitalizationRejectsAfterInvocationManagerThatDoesNotSupportMethodInvocation() throws Exception {
        final AfterInvocationManager aim = mock(AfterInvocationManager.class);
        when(aim.supports(MethodInvocation.class)).thenReturn(false);
        interceptor.setAfterInvocationManager(aim);
        interceptor.afterPropertiesSet();
    }

    @Test(expected=IllegalArgumentException.class)
    public void initializationFailsIfAccessDecisionManagerRejectsConfigAttributes() throws Exception {
        when(adm.supports(any(ConfigAttribute.class))).thenReturn(false);
        interceptor.afterPropertiesSet();
    }

    @Test
    public void validationNotAttemptedIfIsValidateConfigAttributesSetToFalse() throws Exception {
        when(adm.supports(MethodInvocation.class)).thenReturn(true);
        when(mds.supports(MethodInvocation.class)).thenReturn(true);
        interceptor.setValidateConfigAttributes(false);
        interceptor.afterPropertiesSet();
        verify(mds, never()).getAllConfigAttributes();
        verify(adm, never()).supports(any(ConfigAttribute.class));
    }

    @Test
    public void validationNotAttemptedIfMethodSecurityMetadataSourceReturnsNullForAttributes() throws Exception {
        when(adm.supports(MethodInvocation.class)).thenReturn(true);
        when(mds.supports(MethodInvocation.class)).thenReturn(true);
        when(mds.getAllConfigAttributes()).thenReturn(null);

        interceptor.setValidateConfigAttributes(true);
        interceptor.afterPropertiesSet();
        verify(adm, never()).supports(any(ConfigAttribute.class));
    }

    @Test
    public void callingAPublicMethodFacadeWillNotRepeatSecurityChecksWhenPassedToTheSecuredMethodItFronts() {
        mdsReturnsNull();
        String result = advisedTarget.publicMakeLowerCase("HELLO");
        assertEquals("hello Authentication empty", result);
    }

    @Test
    public void callingAPublicMethodWhenPresentingAnAuthenticationObjectDoesntChangeItsAuthenticatedProperty() {
        mdsReturnsNull();
        SecurityContextHolder.getContext().setAuthentication(token);
        assertEquals("hello org.springframework.security.authentication.TestingAuthenticationToken false",
                advisedTarget.publicMakeLowerCase("HELLO"));
        assertTrue(!token.isAuthenticated());
    }

    @Test(expected=AuthenticationException.class)
    public void callIsntMadeWhenAuthenticationManagerRejectsAuthentication() throws Exception {
        final TestingAuthenticationToken token = new TestingAuthenticationToken("Test", "Password");
        SecurityContextHolder.getContext().setAuthentication(token);

        mdsReturnsUserRole();
        when(authman.authenticate(token)).thenThrow(new BadCredentialsException("rejected"));

        advisedTarget.makeLowerCase("HELLO");
    }

    @Test
    public void callSucceedsIfAccessDecisionManagerGrantsAccess() throws Exception {
        token.setAuthenticated(true);
        interceptor.setPublishAuthorizationSuccess(true);
        SecurityContextHolder.getContext().setAuthentication(token);
        mdsReturnsUserRole();

        String result = advisedTarget.makeLowerCase("HELLO");

        // Note we check the isAuthenticated remained true in following line
        assertEquals("hello org.springframework.security.authentication.TestingAuthenticationToken true", result);
        verify(eventPublisher).publishEvent(any(AuthorizedEvent.class));
    }

    @Test
    public void callIsntMadeWhenAccessDecisionManagerRejectsAccess() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(token);
        // Use mocked target to make sure invocation doesn't happen (not in expectations so test would fail)
        createTarget(true);
        mdsReturnsUserRole();
        when(authman.authenticate(token)).thenReturn(token);
        doThrow(new AccessDeniedException("rejected")).when(adm).decide(any(Authentication.class), any(MethodInvocation.class), any(List.class));

        try {
            advisedTarget.makeUpperCase("HELLO");
            fail();
        } catch (AccessDeniedException expected) {
        }
        verify(eventPublisher).publishEvent(any(AuthorizationFailureEvent.class));
    }

    @Test(expected=IllegalArgumentException.class)
    public void rejectsNullSecuredObjects() throws Throwable {
        interceptor.invoke(null);
    }

    @Test
    public void runAsReplacementIsCorrectlySet() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(token);
        token.setAuthenticated(true);
        final RunAsManager runAs = mock(RunAsManager.class);
        final RunAsUserToken runAsToken =
            new RunAsUserToken("key", "someone", "creds", token.getAuthorities(), TestingAuthenticationToken.class);
        interceptor.setRunAsManager(runAs);
        mdsReturnsUserRole();
        when(runAs.buildRunAs(eq(token), any(MethodInvocation.class), any(List.class))).thenReturn(runAsToken);

        String result = advisedTarget.makeUpperCase("hello");
        assertEquals("HELLO org.springframework.security.access.intercept.RunAsUserToken true", result);
        // Check we've changed back
        assertEquals(token, SecurityContextHolder.getContext().getAuthentication());
    }

    @Test(expected=AuthenticationCredentialsNotFoundException.class)
    public void emptySecurityContextIsRejected() throws Exception {
        mdsReturnsUserRole();
        advisedTarget.makeUpperCase("hello");
    }

    @Test
    public void afterInvocationManagerIsNotInvokedIfExceptionIsRaised() throws Throwable {
        MethodInvocation mi = mock(MethodInvocation.class);
        token.setAuthenticated(true);
        SecurityContextHolder.getContext().setAuthentication(token);
        mdsReturnsUserRole();

        AfterInvocationManager aim = mock(AfterInvocationManager.class);
        interceptor.setAfterInvocationManager(aim);

        when(mi.proceed()).thenThrow(new Throwable());

        try {
            interceptor.invoke(mi);
            fail("Expected exception");
        } catch (Throwable expected) {
        }

        verifyZeroInteractions(aim);
    }

    void mdsReturnsNull() {
        when(mds.getAttributes(any(MethodInvocation.class))).thenReturn(null);
    }

    void mdsReturnsUserRole() {
        when(mds.getAttributes(any(MethodInvocation.class))).thenReturn(SecurityConfig.createList("ROLE_USER"));
    }
}
