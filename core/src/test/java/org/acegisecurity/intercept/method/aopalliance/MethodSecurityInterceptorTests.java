/* Copyright 2004 Acegi Technology Pty Limited
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

package net.sf.acegisecurity.intercept.method.aopalliance;

import junit.framework.TestCase;

import net.sf.acegisecurity.AccessDecisionManager;
import net.sf.acegisecurity.AccessDeniedException;
import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.AuthenticationCredentialsNotFoundException;
import net.sf.acegisecurity.ConfigAttribute;
import net.sf.acegisecurity.ConfigAttributeDefinition;
import net.sf.acegisecurity.GrantedAuthority;
import net.sf.acegisecurity.GrantedAuthorityImpl;
import net.sf.acegisecurity.ITargetObject;
import net.sf.acegisecurity.MockAccessDecisionManager;
import net.sf.acegisecurity.MockAuthenticationManager;
import net.sf.acegisecurity.MockMethodInvocation;
import net.sf.acegisecurity.MockRunAsManager;
import net.sf.acegisecurity.RunAsManager;
import net.sf.acegisecurity.context.ContextHolder;
import net.sf.acegisecurity.context.ContextImpl;
import net.sf.acegisecurity.context.SecureContext;
import net.sf.acegisecurity.context.SecureContextImpl;
import net.sf.acegisecurity.intercept.method.AbstractMethodDefinitionSource;
import net.sf.acegisecurity.intercept.method.MockMethodDefinitionSource;
import net.sf.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import net.sf.acegisecurity.runas.RunAsManagerImpl;

import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;

import java.lang.reflect.Method;

import java.util.Iterator;


/**
 * Tests {@link MethodSecurityInterceptor}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class MethodSecurityInterceptorTests extends TestCase {
    //~ Constructors ===========================================================

    public MethodSecurityInterceptorTests() {
        super();
    }

    public MethodSecurityInterceptorTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(MethodSecurityInterceptorTests.class);
    }

    public void testCallingAPublicMethodFacadeWillNotRepeatSecurityChecksWhenPassedToTheSecuredMethodItFronts()
        throws Exception {
        ITargetObject target = makeInterceptedTarget();
        String result = target.publicMakeLowerCase("HELLO");
        assertEquals("hello ContextHolder Not Security Aware", result);

        ContextHolder.setContext(null);
    }

    public void testCallingAPublicMethodWhenPresentingASecureContextButWithoutAnyAuthenticationObject()
        throws Exception {
        SecureContext context = new SecureContextImpl();
        ContextHolder.setContext(context);

        ITargetObject target = makeInterceptedTarget();
        String result = target.publicMakeLowerCase("HELLO");
        assertEquals("hello Authentication empty", result);

        ContextHolder.setContext(null);
    }

    public void testCallingAPublicMethodWhenPresentingAnAuthenticationObjectWillProperlySetItsIsAuthenticatedProperty()
        throws Exception {
        SecureContext context = new SecureContextImpl();
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("Test",
                "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("MOCK_THIS_IS_NOT_REQUIRED_AS_IT_IS_PUBLIC")});
        assertTrue(!token.isAuthenticated());
        context.setAuthentication(token);
        ContextHolder.setContext(context);

        ITargetObject target = makeInterceptedTarget();
        String result = target.publicMakeLowerCase("HELLO");
        assertEquals("hello net.sf.acegisecurity.providers.UsernamePasswordAuthenticationToken false",
            result);

        ContextHolder.setContext(null);
    }

    public void testDeniesWhenAppropriate() throws Exception {
        SecureContext context = new SecureContextImpl();
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("Test",
                "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("MOCK_NO_BENEFIT_TO_THIS_GRANTED_AUTHORITY")});
        context.setAuthentication(token);
        ContextHolder.setContext(context);

        ITargetObject target = makeInterceptedTarget();

        try {
            target.makeUpperCase("HELLO");
            fail("Should have thrown AccessDeniedException");
        } catch (AccessDeniedException expected) {
            assertTrue(true);
        }

        ContextHolder.setContext(null);
    }

    public void testGetters() {
        MockAccessDecisionManager accessDecision = new MockAccessDecisionManager();
        MockRunAsManager runAs = new MockRunAsManager();
        MockAuthenticationManager authManager = new MockAuthenticationManager();
        MockMethodDefinitionSource methodSource = new MockMethodDefinitionSource(false,
                true);

        MethodSecurityInterceptor si = new MethodSecurityInterceptor();
        si.setAccessDecisionManager(accessDecision);
        si.setRunAsManager(runAs);
        si.setAuthenticationManager(authManager);
        si.setObjectDefinitionSource(methodSource);

        assertEquals(accessDecision, si.getAccessDecisionManager());
        assertEquals(runAs, si.getRunAsManager());
        assertEquals(authManager, si.getAuthenticationManager());
        assertEquals(methodSource, si.getObjectDefinitionSource());
    }

    public void testMethodCallWithRunAsReplacement() throws Exception {
        SecureContext context = new SecureContextImpl();
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("Test",
                "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("MOCK_UPPER")});
        context.setAuthentication(token);
        ContextHolder.setContext(context);

        ITargetObject target = makeInterceptedTarget();
        String result = target.makeUpperCase("hello");
        assertEquals("HELLO net.sf.acegisecurity.MockRunAsAuthenticationToken true",
            result);

        ContextHolder.setContext(null);
    }

    public void testMethodCallWithoutRunAsReplacement()
        throws Exception {
        SecureContext context = new SecureContextImpl();
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("Test",
                "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("MOCK_LOWER")});
        assertTrue(!token.isAuthenticated());
        context.setAuthentication(token);
        ContextHolder.setContext(context);

        ITargetObject target = makeInterceptedTarget();
        String result = target.makeLowerCase("HELLO");

        // Note we check the isAuthenticated becomes true in following line
        assertEquals("hello net.sf.acegisecurity.providers.UsernamePasswordAuthenticationToken true",
            result);

        ContextHolder.setContext(null);
    }

    public void testRejectionOfEmptyContextHolder() throws Exception {
        ITargetObject target = makeInterceptedTarget();

        try {
            target.makeUpperCase("hello");
            fail(
                "Should have thrown AuthenticationCredentialsNotFoundException");
        } catch (AuthenticationCredentialsNotFoundException expected) {
            assertTrue(true);
        }
    }

    public void testRejectionOfNonSecureContextOnContextHolder()
        throws Exception {
        ContextHolder.setContext(new ContextImpl());

        ITargetObject target = makeInterceptedTarget();

        try {
            target.makeUpperCase("hello");
            fail(
                "Should have thrown AuthenticationCredentialsNotFoundException");
        } catch (AuthenticationCredentialsNotFoundException expected) {
            assertTrue(true);
        }

        ContextHolder.setContext(null);
    }

    public void testRejectionOfSecureContextThatContainsNoAuthenticationObject()
        throws Exception {
        ContextHolder.setContext(new SecureContextImpl());

        ITargetObject target = makeInterceptedTarget();

        try {
            target.makeUpperCase("hello");
            fail(
                "Should have thrown AuthenticationCredentialsNotFoundException");
        } catch (AuthenticationCredentialsNotFoundException expected) {
            assertTrue(true);
        }

        ContextHolder.setContext(null);
    }

    public void testRejectsAccessDecisionManagersThatDoNotSupportMethodInvocation() {
        MethodSecurityInterceptor si = new MethodSecurityInterceptor();
        si.setAccessDecisionManager(new MockAccessDecisionManagerWhichOnlySupportsStrings());
        si.setAuthenticationManager(new MockAuthenticationManager());
        si.setObjectDefinitionSource(new MockMethodDefinitionSource(false, true));
        si.setRunAsManager(new MockRunAsManager());

        try {
            si.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("AccessDecisionManager does not support MethodInvocation",
                expected.getMessage());
        }
    }

    public void testRejectsCallsWhenObjectDefinitionSourceDoesNotSupportObject()
        throws Throwable {
        MethodSecurityInterceptor interceptor = new MethodSecurityInterceptor();
        interceptor.setObjectDefinitionSource(new MockObjectDefinitionSourceWhichOnlySupportsStrings());

        try {
            interceptor.invoke(new MockMethodInvocation());
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().startsWith("ObjectDefinitionSource does not support objects of type"));
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

    public void testRejectsRunAsManagersThatDoNotSupportMethodInvocation() {
        MethodSecurityInterceptor si = new MethodSecurityInterceptor();
        si.setAccessDecisionManager(new MockAccessDecisionManager());
        si.setAuthenticationManager(new MockAuthenticationManager());
        si.setObjectDefinitionSource(new MockMethodDefinitionSource(false, true));
        si.setRunAsManager(new MockRunAsManagerWhichOnlySupportsStrings());

        try {
            si.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("RunAsManager does not support MethodInvocation",
                expected.getMessage());
        }
    }

    public void testStartupCheckForAccessDecisionManager() {
        MethodSecurityInterceptor si = new MethodSecurityInterceptor();
        si.setRunAsManager(new MockRunAsManager());
        si.setAuthenticationManager(new MockAuthenticationManager());

        si.setObjectDefinitionSource(new MockMethodDefinitionSource(false, true));

        try {
            si.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("An AccessDecisionManager is required",
                expected.getMessage());
        }
    }

    public void testStartupCheckForAuthenticationManager() {
        MethodSecurityInterceptor si = new MethodSecurityInterceptor();
        si.setAccessDecisionManager(new MockAccessDecisionManager());
        si.setRunAsManager(new MockRunAsManager());

        si.setObjectDefinitionSource(new MockMethodDefinitionSource(false, true));

        try {
            si.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("An AuthenticationManager is required",
                expected.getMessage());
        }
    }

    public void testStartupCheckForMethodDefinitionSource() {
        MethodSecurityInterceptor si = new MethodSecurityInterceptor();
        si.setAccessDecisionManager(new MockAccessDecisionManager());
        si.setAuthenticationManager(new MockAuthenticationManager());

        try {
            si.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("An ObjectDefinitionSource is required",
                expected.getMessage());
        }
    }

    public void testStartupCheckForRunAsManager() {
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

    public void testValidationFailsIfInvalidAttributePresented() {
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

    public void testValidationNotAttemptedIfIsValidateConfigAttributesSetToFalse() {
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

    public void testValidationNotAttemptedIfMethodDefinitionSourceCannotReturnIterator() {
        MethodSecurityInterceptor si = new MethodSecurityInterceptor();
        si.setAccessDecisionManager(new MockAccessDecisionManager());
        si.setRunAsManager(new MockRunAsManager());
        si.setAuthenticationManager(new MockAuthenticationManager());

        assertTrue(si.isValidateConfigAttributes()); // check default
        si.setObjectDefinitionSource(new MockMethodDefinitionSource(true, false));
        si.afterPropertiesSet();
        assertTrue(true);
    }

    private ITargetObject makeInterceptedTarget() {
        ApplicationContext context = new ClassPathXmlApplicationContext(
                "net/sf/acegisecurity/intercept/method/aopalliance/applicationContext.xml");

        return (ITargetObject) context.getBean("target");
    }

    //~ Inner Classes ==========================================================

    private class MockAccessDecisionManagerWhichOnlySupportsStrings
        implements AccessDecisionManager {
        public void decide(Authentication authentication, Object object,
            ConfigAttributeDefinition config) throws AccessDeniedException {
            throw new UnsupportedOperationException(
                "mock method not implemented");
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

    private class MockObjectDefinitionSourceWhichOnlySupportsStrings
        extends AbstractMethodDefinitionSource {
        public Iterator getConfigAttributeDefinitions() {
            throw new UnsupportedOperationException(
                "mock method not implemented");
        }

        public boolean supports(Class clazz) {
            if (String.class.isAssignableFrom(clazz)) {
                return true;
            } else {
                return false;
            }
        }

        protected ConfigAttributeDefinition lookupAttributes(Method method) {
            throw new UnsupportedOperationException(
                "mock method not implemented");
        }
    }

    private class MockRunAsManagerWhichOnlySupportsStrings
        implements RunAsManager {
        public Authentication buildRunAs(Authentication authentication,
            Object object, ConfigAttributeDefinition config) {
            throw new UnsupportedOperationException(
                "mock method not implemented");
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
