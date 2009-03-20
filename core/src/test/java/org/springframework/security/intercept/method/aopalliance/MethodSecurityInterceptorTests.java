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

package org.springframework.security.intercept.method.aopalliance;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.List;

import org.aopalliance.intercept.MethodInvocation;
import org.jmock.Expectations;
import org.jmock.Mockery;
import org.jmock.integration.junit4.JUnit4Mockery;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.aop.framework.ProxyFactory;
import org.springframework.security.AccessDecisionManager;
import org.springframework.security.AccessDeniedException;
import org.springframework.security.AfterInvocationManager;
import org.springframework.security.AuthenticationCredentialsNotFoundException;
import org.springframework.security.AuthenticationException;
import org.springframework.security.AuthenticationManager;
import org.springframework.security.BadCredentialsException;
import org.springframework.security.ConfigAttribute;
import org.springframework.security.ITargetObject;
import org.springframework.security.RunAsManager;
import org.springframework.security.SecurityConfig;
import org.springframework.security.TargetObject;
import org.springframework.security.context.SecurityContextHolder;
import org.springframework.security.intercept.method.MethodSecurityMetadataSource;
import org.springframework.security.providers.TestingAuthenticationToken;
import org.springframework.security.runas.RunAsUserToken;

/**
 * Tests {@link MethodSecurityInterceptor}.
 *
 * @author Ben Alex
 * @version $Id$
 */
@SuppressWarnings("unchecked")
public class MethodSecurityInterceptorTests {
    private Mockery jmock = new JUnit4Mockery();
    private TestingAuthenticationToken token;
    private MethodSecurityInterceptor interceptor;
    private ITargetObject realTarget;
    private ITargetObject advisedTarget;
    private AccessDecisionManager adm;
    private MethodSecurityMetadataSource mds;
    private AuthenticationManager authman;

    private Expectations mdsWillReturnNullFromGetAttributes;
    private Expectations mdsWillReturnROLE_USERFromGetAttributes;

    //~ Methods ========================================================================================================

    @Before
    public final void setUp() throws Exception {
        SecurityContextHolder.clearContext();
        token = new TestingAuthenticationToken("Test", "Password");
        interceptor = new MethodSecurityInterceptor();
        adm = jmock.mock(AccessDecisionManager.class);
        authman = jmock.mock(AuthenticationManager.class);
        mds = jmock.mock(MethodSecurityMetadataSource.class);
        interceptor.setAccessDecisionManager(adm);
        interceptor.setAuthenticationManager(authman);
        interceptor.setSecurityMetadataSource(mds);
        createTarget(false);

        mdsWillReturnNullFromGetAttributes = new Expectations() {{
            oneOf(mds).getAttributes(with(any(MethodInvocation.class))); will (returnValue(null));
        }};
        mdsWillReturnROLE_USERFromGetAttributes = new Expectations() {{
            oneOf(mds).getAttributes(with(any(MethodInvocation.class))); will (returnValue(SecurityConfig.createList("ROLE_USER")));
        }};
    }

    @After
    public void tearDown() throws Exception {
        SecurityContextHolder.clearContext();
    }

    private void createTarget(boolean useMock) {
        realTarget = useMock ? jmock.mock(ITargetObject.class) : new TargetObject();
        ProxyFactory pf = new ProxyFactory(realTarget);
        pf.addAdvice(interceptor);
        advisedTarget = (ITargetObject) pf.getProxy();
    }

    @Test
    public void gettersReturnExpectedData() {
        RunAsManager runAs = jmock.mock(RunAsManager.class);
        AfterInvocationManager aim = jmock.mock(AfterInvocationManager.class);
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
        jmock.checking(new Expectations() {{
           oneOf(mds).supports(MethodInvocation.class); will(returnValue(false));
        }});
        interceptor.afterPropertiesSet();
    }

    @Test(expected=IllegalArgumentException.class)
    public void initializationRejectsAccessDecisionManagerThatDoesNotSupportMethodInvocation() throws Exception {
        jmock.checking(new Expectations() {{
            oneOf(mds).supports(MethodInvocation.class); will(returnValue(true));
            oneOf(adm).supports(MethodInvocation.class); will(returnValue(false));
         }});
         interceptor.afterPropertiesSet();
    }

    @Test(expected=IllegalArgumentException.class)
    public void intitalizationRejectsRunAsManagerThatDoesNotSupportMethodInvocation() throws Exception {
        final RunAsManager ram = jmock.mock(RunAsManager.class);
        jmock.checking(new Expectations() {{
            ignoring(mds);
            oneOf(ram).supports(MethodInvocation.class); will(returnValue(false));
        }});
        interceptor.setRunAsManager(ram);
        interceptor.afterPropertiesSet();
    }

    @Test(expected=IllegalArgumentException.class)
    public void intitalizationRejectsAfterInvocationManagerThatDoesNotSupportMethodInvocation() throws Exception {
        final AfterInvocationManager aim = jmock.mock(AfterInvocationManager.class);
        jmock.checking(new Expectations() {{
            oneOf(aim).supports(MethodInvocation.class); will(returnValue(false));
            ignoring(anything());
        }});
        interceptor.setAfterInvocationManager(aim);
        interceptor.afterPropertiesSet();
    }

    @Test(expected=IllegalArgumentException.class)
    public void initializationFailsIfAccessDecisionManagerRejectsConfigAttributes() throws Exception {
        jmock.checking(new Expectations() {{
            oneOf(adm).supports(with(aNonNull(ConfigAttribute.class))); will(returnValue(false));
            ignoring(anything());
        }});
        interceptor.afterPropertiesSet();
    }

    @Test
    public void validationNotAttemptedIfIsValidateConfigAttributesSetToFalse() throws Exception {
        jmock.checking(new Expectations() {{
            oneOf(mds).supports(MethodInvocation.class); will(returnValue(true));
            oneOf(adm).supports(MethodInvocation.class); will(returnValue(true));
            never(mds).getAllConfigAttributes();
            never(adm).supports(with(any(ConfigAttribute.class)));
        }});
        interceptor.setValidateConfigAttributes(false);
        interceptor.afterPropertiesSet();
    }

    @Test
    public void validationNotAttemptedIfMethodSecurityMetadataSourceReturnsNullForAttributes() throws Exception {
        jmock.checking(new Expectations() {{
            oneOf(mds).supports(MethodInvocation.class); will(returnValue(true));
            oneOf(adm).supports(MethodInvocation.class); will(returnValue(true));
            oneOf(mds).getAllConfigAttributes(); will(returnValue(null));
            never(adm).supports(with(any(ConfigAttribute.class)));
        }});
        interceptor.setValidateConfigAttributes(true);
        interceptor.afterPropertiesSet();
    }

    @Test
    public void callingAPublicMethodFacadeWillNotRepeatSecurityChecksWhenPassedToTheSecuredMethodItFronts() {
        jmock.checking(mdsWillReturnNullFromGetAttributes);
        String result = advisedTarget.publicMakeLowerCase("HELLO");
        assertEquals("hello Authentication empty", result);
        jmock.assertIsSatisfied();
    }

    @Test
    public void callingAPublicMethodWhenPresentingAnAuthenticationObjectDoesntChangeItsAuthenticatedProperty() {
        jmock.checking(mdsWillReturnNullFromGetAttributes);
        SecurityContextHolder.getContext().setAuthentication(token);
        assertEquals("hello org.springframework.security.providers.TestingAuthenticationToken false",
                advisedTarget.publicMakeLowerCase("HELLO"));
        assertTrue(!token.isAuthenticated());
    }

    @Test(expected=AuthenticationException.class)
    public void callIsWhenAuthenticationManagerRejectsAuthentication() throws Exception {
        final TestingAuthenticationToken token = new TestingAuthenticationToken("Test", "Password");
        SecurityContextHolder.getContext().setAuthentication(token);

        jmock.checking(mdsWillReturnROLE_USERFromGetAttributes);
        jmock.checking(new Expectations() {{
            oneOf(authman).authenticate(token); will(throwException(new BadCredentialsException("rejected")));
        }});

        advisedTarget.makeLowerCase("HELLO");
    }

    @Test
    public void callSucceedsIfAccessDecisionManagerGrantsAccess() throws Exception {
        token.setAuthenticated(true);
        SecurityContextHolder.getContext().setAuthentication(token);
        jmock.checking(mdsWillReturnROLE_USERFromGetAttributes);
        jmock.checking(new Expectations() {{
           oneOf(adm).decide(with(token), with(aNonNull(MethodInvocation.class)), with(aNonNull(List.class)));
        }});

        String result = advisedTarget.makeLowerCase("HELLO");

        // Note we check the isAuthenticated remained true in following line
        assertEquals("hello org.springframework.security.providers.TestingAuthenticationToken true", result);
    }

    @Test(expected=AccessDeniedException.class)
    public void callIsntMadeWhenAccessDecisionManagerRejectsAccess() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(token);
        // Use mocked target to make sure invocation doesn't happen (not in expectations so test would fail)
        createTarget(true);
        jmock.checking(mdsWillReturnROLE_USERFromGetAttributes);
        jmock.checking(new Expectations() {{
            oneOf(authman).authenticate(token); will(returnValue(token));
            oneOf(adm).decide(with(token), with(aNonNull(MethodInvocation.class)), with(aNonNull(List.class)));
            will(throwException(new AccessDeniedException("rejected")));
        }});

        advisedTarget.makeUpperCase("HELLO");
    }

    @Test(expected=IllegalArgumentException.class)
    public void rejectsNullSecuredObjects() throws Throwable {
        interceptor.invoke(null);
    }

    @Test
    public void runAsReplacementIsCorrectlySet() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(token);
        token.setAuthenticated(true);
        final RunAsManager runAs = jmock.mock(RunAsManager.class);
        final RunAsUserToken runAsToken =
            new RunAsUserToken("key", "someone", "creds", token.getAuthorities(), TestingAuthenticationToken.class);
        interceptor.setRunAsManager(runAs);
        jmock.checking(mdsWillReturnROLE_USERFromGetAttributes);
        jmock.checking(new Expectations() {{
            oneOf(runAs).buildRunAs(with(token), with(aNonNull(MethodInvocation.class)), with(aNonNull(List.class)));
            will(returnValue(runAsToken));
            ignoring(anything());
        }});

        String result = advisedTarget.makeUpperCase("hello");
        assertEquals("HELLO org.springframework.security.runas.RunAsUserToken true", result);
        // Check we've changed back
        assertEquals(token, SecurityContextHolder.getContext().getAuthentication());
    }

    @Test(expected=AuthenticationCredentialsNotFoundException.class)
    public void emptySecurityContextIsRejected() throws Exception {
        jmock.checking(new Expectations() {{
            ignoring(anything());
        }});
        advisedTarget.makeUpperCase("hello");
    }
}
