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

package net.sf.acegisecurity;

import junit.framework.TestCase;

import net.sf.acegisecurity.context.ContextHolder;
import net.sf.acegisecurity.context.ContextImpl;
import net.sf.acegisecurity.context.SecureContext;
import net.sf.acegisecurity.context.SecureContextImpl;
import net.sf.acegisecurity.providers.UsernamePasswordAuthenticationToken;

import org.aopalliance.intercept.MethodInvocation;

import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.beans.factory.support.PropertiesBeanDefinitionReader;

import java.util.Iterator;
import java.util.List;
import java.util.Properties;
import java.util.Vector;


/**
 * Tests {@link SecurityInterceptor}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class SecurityInterceptorTests extends TestCase {
    //~ Constructors ===========================================================

    public SecurityInterceptorTests() {
        super();
    }

    public SecurityInterceptorTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(SecurityInterceptorTests.class);
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

        SecurityInterceptor si = new SecurityInterceptor();
        si.setAccessDecisionManager(accessDecision);
        si.setRunAsManager(runAs);
        si.setAuthenticationManager(authManager);
        si.setMethodDefinitionSource(methodSource);

        assertEquals(accessDecision, si.getAccessDecisionManager());
        assertEquals(runAs, si.getRunAsManager());
        assertEquals(authManager, si.getAuthenticationManager());
        assertEquals(methodSource, si.getMethodDefinitionSource());
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

    public void testStartupCheckForAccessDecisionManager() {
        SecurityInterceptor si = new SecurityInterceptor();
        si.setRunAsManager(new MockRunAsManager());
        si.setAuthenticationManager(new MockAuthenticationManager());

        si.setMethodDefinitionSource(new MockMethodDefinitionSource(false, true));

        try {
            si.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("An AccessDecisionManager is required",
                expected.getMessage());
        }
    }

    public void testStartupCheckForAuthenticationManager() {
        SecurityInterceptor si = new SecurityInterceptor();
        si.setAccessDecisionManager(new MockAccessDecisionManager());
        si.setRunAsManager(new MockRunAsManager());

        si.setMethodDefinitionSource(new MockMethodDefinitionSource(false, true));

        try {
            si.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("An AuthenticationManager is required",
                expected.getMessage());
        }
    }

    public void testStartupCheckForMethodDefinitionSource() {
        SecurityInterceptor si = new SecurityInterceptor();
        si.setAccessDecisionManager(new MockAccessDecisionManager());
        si.setRunAsManager(new MockRunAsManager());
        si.setAuthenticationManager(new MockAuthenticationManager());

        try {
            si.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("A MethodDefinitionSource is required",
                expected.getMessage());
        }
    }

    public void testStartupCheckForRunAsManager() {
        SecurityInterceptor si = new SecurityInterceptor();
        si.setAccessDecisionManager(new MockAccessDecisionManager());
        si.setAuthenticationManager(new MockAuthenticationManager());

        si.setMethodDefinitionSource(new MockMethodDefinitionSource(false, true));

        try {
            si.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("A RunAsManager is required", expected.getMessage());
        }
    }

    public void testValidationFailsIfInvalidAttributePresented() {
        SecurityInterceptor si = new SecurityInterceptor();
        si.setAccessDecisionManager(new MockAccessDecisionManager());
        si.setRunAsManager(new MockRunAsManager());
        si.setAuthenticationManager(new MockAuthenticationManager());

        assertTrue(si.isValidateConfigAttributes()); // check default
        si.setMethodDefinitionSource(new MockMethodDefinitionSource(true, true));

        try {
            si.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("Unsupported configuration attributes: [ANOTHER_INVALID, INVALID_ATTRIBUTE]",
                expected.getMessage());
        }
    }

    public void testValidationNotAttemptedIfIsValidateConfigAttributesSetToFalse() {
        SecurityInterceptor si = new SecurityInterceptor();
        si.setAccessDecisionManager(new MockAccessDecisionManager());
        si.setRunAsManager(new MockRunAsManager());
        si.setAuthenticationManager(new MockAuthenticationManager());

        assertTrue(si.isValidateConfigAttributes()); // check default
        si.setValidateConfigAttributes(false);
        assertTrue(!si.isValidateConfigAttributes()); // check changed

        si.setMethodDefinitionSource(new MockMethodDefinitionSource(true, true));
        si.afterPropertiesSet();
        assertTrue(true);
    }

    public void testValidationNotAttemptedIfMethodDefinitionSourceCannotReturnIterator() {
        SecurityInterceptor si = new SecurityInterceptor();
        si.setAccessDecisionManager(new MockAccessDecisionManager());
        si.setRunAsManager(new MockRunAsManager());
        si.setAuthenticationManager(new MockAuthenticationManager());

        assertTrue(si.isValidateConfigAttributes()); // check default
        si.setMethodDefinitionSource(new MockMethodDefinitionSource(true, false));
        si.afterPropertiesSet();
        assertTrue(true);
    }

    private ITargetObject makeInterceptedTarget() {
        String PREFIX = "beans.";
        DefaultListableBeanFactory lbf = new DefaultListableBeanFactory();
        Properties p = new Properties();
        p.setProperty(PREFIX + "authentication.class",
            "net.sf.acegisecurity.MockAuthenticationManager");
        p.setProperty(PREFIX + "accessDecision.class",
            "net.sf.acegisecurity.MockAccessDecisionManager");
        p.setProperty(PREFIX + "runAs.class",
            "net.sf.acegisecurity.MockRunAsManager");

        p.setProperty(PREFIX + "securityInterceptor.class",
            "net.sf.acegisecurity.SecurityInterceptor");
        p.setProperty(PREFIX + "securityInterceptor.authenticationManager(ref)",
            "authentication");
        p.setProperty(PREFIX + "securityInterceptor.accessDecisionManager(ref)",
            "accessDecision");
        p.setProperty(PREFIX + "securityInterceptor.runAsManager(ref)", "runAs");
        p.setProperty(PREFIX + "securityInterceptor.methodDefinitionSource",
            "net.sf.acegisecurity.ITargetObject.makeLower*=MOCK_LOWER\r\nnet.sf.acegisecurity.ITargetObject.makeUpper*=MOCK_UPPER,RUN_AS");

        p.setProperty(PREFIX + "targetObject.class",
            "net.sf.acegisecurity.TargetObject");
        p.setProperty(PREFIX + "target.class",
            "org.springframework.aop.framework.ProxyFactoryBean");
        p.setProperty(PREFIX + "target.proxyInterfaces",
            "net.sf.acegisecurity.ITargetObject");
        p.setProperty(PREFIX + "target.interceptorNames",
            "securityInterceptor,targetObject");

        (new PropertiesBeanDefinitionReader(lbf)).registerBeanDefinitions(p,
            PREFIX);

        return (ITargetObject) lbf.getBean("target");
    }

    //~ Inner Classes ==========================================================

    private class MockMethodDefinitionSource implements MethodDefinitionSource {
        private List list;
        private boolean returnAnIterator;

        public MockMethodDefinitionSource(boolean includeInvalidAttributes,
            boolean returnAnIteratorWhenRequested) {
            returnAnIterator = returnAnIteratorWhenRequested;
            list = new Vector();

            ConfigAttributeDefinition def1 = new ConfigAttributeDefinition();
            def1.addConfigAttribute(new SecurityConfig("MOCK_LOWER"));
            list.add(def1);

            if (includeInvalidAttributes) {
                ConfigAttributeDefinition def2 = new ConfigAttributeDefinition();
                def2.addConfigAttribute(new SecurityConfig("MOCK_LOWER"));
                def2.addConfigAttribute(new SecurityConfig("INVALID_ATTRIBUTE"));
                list.add(def2);
            }

            ConfigAttributeDefinition def3 = new ConfigAttributeDefinition();
            def3.addConfigAttribute(new SecurityConfig("MOCK_UPPER"));
            def3.addConfigAttribute(new SecurityConfig("RUN_AS"));
            list.add(def3);

            if (includeInvalidAttributes) {
                ConfigAttributeDefinition def4 = new ConfigAttributeDefinition();
                def4.addConfigAttribute(new SecurityConfig("MOCK_SOMETHING"));
                def4.addConfigAttribute(new SecurityConfig("ANOTHER_INVALID"));
                list.add(def4);
            }
        }

        private MockMethodDefinitionSource() {
            super();
        }

        public ConfigAttributeDefinition getAttributes(
            MethodInvocation invocation) {
            throw new UnsupportedOperationException(
                "mock method not implemented");
        }

        public Iterator getConfigAttributeDefinitions() {
            if (returnAnIterator) {
                return list.iterator();
            } else {
                return null;
            }
        }
    }
}
