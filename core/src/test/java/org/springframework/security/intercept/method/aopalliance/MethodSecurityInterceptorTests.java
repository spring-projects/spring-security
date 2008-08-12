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

import junit.framework.TestCase;

import org.springframework.security.AccessDecisionManager;
import org.springframework.security.AccessDeniedException;
import org.springframework.security.AfterInvocationManager;
import org.springframework.security.Authentication;
import org.springframework.security.AuthenticationCredentialsNotFoundException;
import org.springframework.security.AuthenticationException;
import org.springframework.security.ConfigAttribute;
import org.springframework.security.ConfigAttributeDefinition;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.GrantedAuthorityImpl;
import org.springframework.security.ITargetObject;
import org.springframework.security.MockAccessDecisionManager;
import org.springframework.security.MockAfterInvocationManager;
import org.springframework.security.MockAuthenticationManager;
import org.springframework.security.MockRunAsManager;
import org.springframework.security.RunAsManager;

import org.springframework.security.context.SecurityContextHolder;

import org.springframework.security.intercept.method.MethodDefinitionSource;
import org.springframework.security.intercept.method.MockMethodDefinitionSource;

import org.springframework.security.providers.UsernamePasswordAuthenticationToken;

import org.springframework.security.runas.RunAsManagerImpl;

import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;

import java.lang.reflect.Method;

import java.util.Collection;


/**
 * Tests {@link MethodSecurityInterceptor}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class MethodSecurityInterceptorTests extends TestCase {
    //~ Constructors ===================================================================================================

    public MethodSecurityInterceptorTests() {
        super();
    }

    public MethodSecurityInterceptorTests(String arg0) {
        super(arg0);
    }

    //~ Methods ========================================================================================================

    public final void setUp() throws Exception {
        super.setUp();
        SecurityContextHolder.clearContext();
    }

    protected void tearDown() throws Exception {
        super.tearDown();
        SecurityContextHolder.clearContext();
    }

    private ITargetObject makeInterceptedTarget() {
        ApplicationContext context = new ClassPathXmlApplicationContext(
                "org/springframework/security/intercept/method/aopalliance/applicationContext.xml");

        return (ITargetObject) context.getBean("target");
    }

    private ITargetObject makeInterceptedTargetRejectsAuthentication() {
        ApplicationContext context = new ClassPathXmlApplicationContext(
                "org/springframework/security/intercept/method/aopalliance/applicationContext.xml");

        MockAuthenticationManager authenticationManager = new MockAuthenticationManager(false);
        MethodSecurityInterceptor si = (MethodSecurityInterceptor) context.getBean("securityInterceptor");
        si.setAuthenticationManager(authenticationManager);

        return (ITargetObject) context.getBean("target");
    }

    private ITargetObject makeInterceptedTargetWithoutAnAfterInvocationManager() {
        ApplicationContext context = new ClassPathXmlApplicationContext(
                "org/springframework/security/intercept/method/aopalliance/applicationContext.xml");

        MethodSecurityInterceptor si = (MethodSecurityInterceptor) context.getBean("securityInterceptor");
        si.setAfterInvocationManager(null);

        return (ITargetObject) context.getBean("target");
    }

    public void testCallingAPublicMethodFacadeWillNotRepeatSecurityChecksWhenPassedToTheSecuredMethodItFronts()
        throws Exception {
        ITargetObject target = makeInterceptedTarget();
        String result = target.publicMakeLowerCase("HELLO");
        assertEquals("hello Authentication empty", result);
    }

    public void testCallingAPublicMethodWhenPresentingAnAuthenticationObjectWillNotChangeItsIsAuthenticatedProperty()
        throws Exception {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("Test", "Password");
        assertTrue(!token.isAuthenticated());
        SecurityContextHolder.getContext().setAuthentication(token);

        // The associated MockAuthenticationManager WILL accept the above UsernamePasswordAuthenticationToken
        ITargetObject target = makeInterceptedTarget();
        String result = target.publicMakeLowerCase("HELLO");
        assertEquals("hello org.springframework.security.providers.UsernamePasswordAuthenticationToken false", result);
    }

    public void testDeniesWhenAppropriate() throws Exception {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("Test", "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("MOCK_NO_BENEFIT_TO_THIS_GRANTED_AUTHORITY")});
        SecurityContextHolder.getContext().setAuthentication(token);

        ITargetObject target = makeInterceptedTarget();

        try {
            target.makeUpperCase("HELLO");
            fail("Should have thrown AccessDeniedException");
        } catch (AccessDeniedException expected) {
            assertTrue(true);
        }
    }

    public void testGetters() {
        MockAccessDecisionManager accessDecision = new MockAccessDecisionManager();
        MockRunAsManager runAs = new MockRunAsManager();
        MockAuthenticationManager authManager = new MockAuthenticationManager();
        MockMethodDefinitionSource methodSource = new MockMethodDefinitionSource(false, true);
        MockAfterInvocationManager afterInvocation = new MockAfterInvocationManager();

        MethodSecurityInterceptor si = new MethodSecurityInterceptor();
        si.setAccessDecisionManager(accessDecision);
        si.setRunAsManager(runAs);
        si.setAuthenticationManager(authManager);
        si.setObjectDefinitionSource(methodSource);
        si.setAfterInvocationManager(afterInvocation);

        assertEquals(accessDecision, si.getAccessDecisionManager());
        assertEquals(runAs, si.getRunAsManager());
        assertEquals(authManager, si.getAuthenticationManager());
        assertEquals(methodSource, si.getObjectDefinitionSource());
        assertEquals(afterInvocation, si.getAfterInvocationManager());
    }

    public void testMethodCallWithRunAsReplacement() throws Exception {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("Test", "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("MOCK_UPPER")});
        SecurityContextHolder.getContext().setAuthentication(token);

        ITargetObject target = makeInterceptedTarget();
        String result = target.makeUpperCase("hello");
        assertEquals("HELLO org.springframework.security.MockRunAsAuthenticationToken true", result);
    }

    public void testMethodCallWithoutRunAsReplacement()
        throws Exception {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("Test", "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("MOCK_LOWER")});
        assertTrue(token.isAuthenticated());
        SecurityContextHolder.getContext().setAuthentication(token);

        ITargetObject target = makeInterceptedTargetWithoutAnAfterInvocationManager();
        String result = target.makeLowerCase("HELLO");

        // Note we check the isAuthenticated remained true in following line
        assertEquals("hello org.springframework.security.providers.UsernamePasswordAuthenticationToken true", result);
    }

    public void testRejectionOfEmptySecurityContext() throws Exception {
        ITargetObject target = makeInterceptedTarget();

        try {
            target.makeUpperCase("hello");
            fail("Should have thrown AuthenticationCredentialsNotFoundException");
        } catch (AuthenticationCredentialsNotFoundException expected) {
            assertTrue(true);
        }
    }

    public void testRejectsAccessDecisionManagersThatDoNotSupportMethodInvocation()
        throws Exception {
        MethodSecurityInterceptor si = new MethodSecurityInterceptor();
        si.setAccessDecisionManager(new MockAccessDecisionManagerWhichOnlySupportsStrings());
        si.setAuthenticationManager(new MockAuthenticationManager());
        si.setObjectDefinitionSource(new MockMethodDefinitionSource(false, true));
        si.setRunAsManager(new MockRunAsManager());

        try {
            si.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("AccessDecisionManager does not support secure object class: interface org.aopalliance.intercept.MethodInvocation",
                expected.getMessage());
        }
    }

    public void testRejectsCallsWhenAuthenticationIsIncorrect()
        throws Exception {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("Test", "Password");
        assertTrue(!token.isAuthenticated());
        SecurityContextHolder.getContext().setAuthentication(token);

        // NB: The associated MockAuthenticationManager WILL reject the above UsernamePasswordAuthenticationToken
        ITargetObject target = makeInterceptedTargetRejectsAuthentication();

        try {
            target.makeLowerCase("HELLO");
            fail("Should have thrown AuthenticationException");
        } catch (AuthenticationException expected) {
            assertTrue(true);
        }
    }

    public void testRejectsCallsWhenObjectDefinitionSourceDoesNotSupportObject()
        throws Throwable {
        MethodSecurityInterceptor interceptor = new MethodSecurityInterceptor();
        interceptor.setObjectDefinitionSource(new MockObjectDefinitionSourceWhichOnlySupportsStrings());
        interceptor.setAccessDecisionManager(new MockAccessDecisionManager());
        interceptor.setAuthenticationManager(new MockAuthenticationManager());
        interceptor.setRunAsManager(new MockRunAsManager());

        try {
            interceptor.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("ObjectDefinitionSource does not support secure object class: interface org.aopalliance.intercept.MethodInvocation",
                expected.getMessage());
        }
    }

    public void testRejectsCallsWhenObjectIsNull() throws Throwable {
        MethodSecurityInterceptor interceptor = new MethodSecurityInterceptor();

        try {
            interceptor.invoke(null);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("Object was null", expected.getMessage());
        }
    }

    public void testRejectsRunAsManagersThatDoNotSupportMethodInvocation()
        throws Exception {
        MethodSecurityInterceptor si = new MethodSecurityInterceptor();
        si.setAccessDecisionManager(new MockAccessDecisionManager());
        si.setAuthenticationManager(new MockAuthenticationManager());
        si.setObjectDefinitionSource(new MockMethodDefinitionSource(false, true));
        si.setRunAsManager(new MockRunAsManagerWhichOnlySupportsStrings());
        si.setAfterInvocationManager(new MockAfterInvocationManager());

        try {
            si.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("RunAsManager does not support secure object class: interface org.aopalliance.intercept.MethodInvocation",
                expected.getMessage());
        }
    }

    public void testStartupCheckForAccessDecisionManager()
        throws Exception {
        MethodSecurityInterceptor si = new MethodSecurityInterceptor();
        si.setRunAsManager(new MockRunAsManager());
        si.setAuthenticationManager(new MockAuthenticationManager());
        si.setAfterInvocationManager(new MockAfterInvocationManager());

        si.setObjectDefinitionSource(new MockMethodDefinitionSource(false, true));

        try {
            si.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("An AccessDecisionManager is required", expected.getMessage());
        }
    }

    public void testStartupCheckForAuthenticationManager()
        throws Exception {
        MethodSecurityInterceptor si = new MethodSecurityInterceptor();
        si.setAccessDecisionManager(new MockAccessDecisionManager());
        si.setRunAsManager(new MockRunAsManager());
        si.setAfterInvocationManager(new MockAfterInvocationManager());

        si.setObjectDefinitionSource(new MockMethodDefinitionSource(false, true));

        try {
            si.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("An AuthenticationManager is required", expected.getMessage());
        }
    }

    public void testStartupCheckForMethodDefinitionSource()
        throws Exception {
        MethodSecurityInterceptor si = new MethodSecurityInterceptor();
        si.setAccessDecisionManager(new MockAccessDecisionManager());
        si.setAuthenticationManager(new MockAuthenticationManager());

        try {
            si.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("An ObjectDefinitionSource is required", expected.getMessage());
        }
    }

    public void testStartupCheckForRunAsManager() throws Exception {
        MethodSecurityInterceptor si = new MethodSecurityInterceptor();
        si.setAccessDecisionManager(new MockAccessDecisionManager());
        si.setAuthenticationManager(new MockAuthenticationManager());
        si.setRunAsManager(null); // Overriding the default

        si.setObjectDefinitionSource(new MockMethodDefinitionSource(false, true));

        try {
            si.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("A RunAsManager is required", expected.getMessage());
        }
    }

    public void testStartupCheckForValidAfterInvocationManager()
        throws Exception {
        MethodSecurityInterceptor si = new MethodSecurityInterceptor();
        si.setRunAsManager(new MockRunAsManager());
        si.setAuthenticationManager(new MockAuthenticationManager());
        si.setAfterInvocationManager(new MockAfterInvocationManagerWhichOnlySupportsStrings());
        si.setAccessDecisionManager(new MockAccessDecisionManager());
        si.setObjectDefinitionSource(new MockMethodDefinitionSource(false, true));

        try {
            si.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().startsWith("AfterInvocationManager does not support secure object class:"));
        }
    }

    public void testValidationFailsIfInvalidAttributePresented()
        throws Exception {
        MethodSecurityInterceptor si = new MethodSecurityInterceptor();
        si.setAccessDecisionManager(new MockAccessDecisionManager());
        si.setAuthenticationManager(new MockAuthenticationManager());
        si.setRunAsManager(new RunAsManagerImpl());

        assertTrue(si.isValidateConfigAttributes()); // check default
        si.setObjectDefinitionSource(new MockMethodDefinitionSource(true, true));

        try {
            si.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("Unsupported configuration attributes: [ANOTHER_INVALID, INVALID_ATTRIBUTE]",
                expected.getMessage());
        }
    }

    public void testValidationNotAttemptedIfIsValidateConfigAttributesSetToFalse()
        throws Exception {
        MethodSecurityInterceptor si = new MethodSecurityInterceptor();
        si.setAccessDecisionManager(new MockAccessDecisionManager());
        si.setAuthenticationManager(new MockAuthenticationManager());

        assertTrue(si.isValidateConfigAttributes()); // check default
        si.setValidateConfigAttributes(false);
        assertTrue(!si.isValidateConfigAttributes()); // check changed

        si.setObjectDefinitionSource(new MockMethodDefinitionSource(true, true));
        si.afterPropertiesSet();
        assertTrue(true);
    }

    public void testValidationNotAttemptedIfMethodDefinitionSourceCannotReturnIterator()
        throws Exception {
        MethodSecurityInterceptor si = new MethodSecurityInterceptor();
        si.setAccessDecisionManager(new MockAccessDecisionManager());
        si.setRunAsManager(new MockRunAsManager());
        si.setAuthenticationManager(new MockAuthenticationManager());

        assertTrue(si.isValidateConfigAttributes()); // check default
        si.setObjectDefinitionSource(new MockMethodDefinitionSource(true, false));
        si.afterPropertiesSet();
        assertTrue(true);
    }

    //~ Inner Classes ==================================================================================================

    private class MockAccessDecisionManagerWhichOnlySupportsStrings implements AccessDecisionManager {
        public void decide(Authentication authentication, Object object, ConfigAttributeDefinition config)
            throws AccessDeniedException {
            throw new UnsupportedOperationException("mock method not implemented");
        }

        public boolean supports(Class clazz) {
            if (String.class.isAssignableFrom(clazz)) {
                return true;
            } else {
                return false;
            }
        }

        public boolean supports(ConfigAttribute attribute) {
            return true;
        }
    }

    private class MockAfterInvocationManagerWhichOnlySupportsStrings implements AfterInvocationManager {
        public Object decide(Authentication authentication, Object object, ConfigAttributeDefinition config,
            Object returnedObject) throws AccessDeniedException {
            throw new UnsupportedOperationException("mock method not implemented");
        }

        public boolean supports(Class clazz) {
            if (String.class.isAssignableFrom(clazz)) {
                return true;
            } else {
                return false;
            }
        }

        public boolean supports(ConfigAttribute attribute) {
            return true;
        }
    }

    private class MockObjectDefinitionSourceWhichOnlySupportsStrings implements MethodDefinitionSource {
        public Collection getConfigAttributeDefinitions() {
            return null;
        }

        public ConfigAttributeDefinition getAttributes(Method method, Class targetClass) {
            throw new UnsupportedOperationException("mock method not implemented");
        }

        public boolean supports(Class clazz) {
            if (String.class.isAssignableFrom(clazz)) {
                return true;
            } else {
                return false;
            }
        }

        public ConfigAttributeDefinition getAttributes(Object object) {
            throw new UnsupportedOperationException("mock method not implemented");
        }
    }

    private class MockRunAsManagerWhichOnlySupportsStrings implements RunAsManager {
        public Authentication buildRunAs(Authentication authentication, Object object, ConfigAttributeDefinition config) {
            throw new UnsupportedOperationException("mock method not implemented");
        }

        public boolean supports(Class clazz) {
            if (String.class.isAssignableFrom(clazz)) {
                return true;
            } else {
                return false;
            }
        }

        public boolean supports(ConfigAttribute attribute) {
            return true;
        }
    }
}
