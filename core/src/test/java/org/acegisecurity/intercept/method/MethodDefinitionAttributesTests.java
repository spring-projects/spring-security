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

package net.sf.acegisecurity.intercept.method;

import junit.framework.TestCase;

import net.sf.acegisecurity.ConfigAttribute;
import net.sf.acegisecurity.ConfigAttributeDefinition;
import net.sf.acegisecurity.GrantedAuthority;
import net.sf.acegisecurity.GrantedAuthorityImpl;
import net.sf.acegisecurity.ITargetObject;
import net.sf.acegisecurity.MockMethodInvocation;
import net.sf.acegisecurity.OtherTargetObject;
import net.sf.acegisecurity.SecurityConfig;
import net.sf.acegisecurity.TargetObject;
import net.sf.acegisecurity.context.ContextHolder;
import net.sf.acegisecurity.context.SecureContext;
import net.sf.acegisecurity.context.SecureContextImpl;
import net.sf.acegisecurity.providers.UsernamePasswordAuthenticationToken;

import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.beans.factory.support.PropertiesBeanDefinitionReader;

import org.springframework.context.support.ClassPathXmlApplicationContext;

import java.lang.reflect.Method;

import java.util.HashSet;
import java.util.Iterator;
import java.util.Properties;
import java.util.Set;


/**
 * Tests {@link MethodDefinitionAttributes}.
 *
 * @author Cameron Braid
 * @author Ben Alex
 * @version $Id$
 */
public class MethodDefinitionAttributesTests extends TestCase {
    //~ Instance fields ========================================================

    ClassPathXmlApplicationContext applicationContext;

    //~ Constructors ===========================================================

    public MethodDefinitionAttributesTests(String a) {
        super(a);
    }

    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(MethodDefinitionAttributesTests.class);
    }

    public void testAttributesForInterfaceTargetObject()
        throws Exception {
        ConfigAttributeDefinition def1 = getConfigAttributeDefinition(ITargetObject.class,
                "countLength", new Class[] {String.class});
        Set set1 = toSet(def1);
        assertTrue(set1.contains(new SecurityConfig("MOCK_INTERFACE")));
        assertTrue(set1.contains(
                new SecurityConfig("MOCK_INTERFACE_METHOD_COUNT_LENGTH")));

        ConfigAttributeDefinition def2 = getConfigAttributeDefinition(ITargetObject.class,
                "makeLowerCase", new Class[] {String.class});
        Set set2 = toSet(def2);
        assertTrue(set2.contains(new SecurityConfig("MOCK_INTERFACE")));
        assertTrue(set2.contains(
                new SecurityConfig("MOCK_INTERFACE_METHOD_MAKE_LOWER_CASE")));

        ConfigAttributeDefinition def3 = getConfigAttributeDefinition(ITargetObject.class,
                "makeUpperCase", new Class[] {String.class});
        Set set3 = toSet(def3);
        assertTrue(set3.contains(new SecurityConfig("MOCK_INTERFACE")));
        assertTrue(set3.contains(
                new SecurityConfig("MOCK_INTERFACE_METHOD_MAKE_UPPER_CASE")));
    }

    public void testAttributesForOtherTargetObject() throws Exception {
        ConfigAttributeDefinition def1 = getConfigAttributeDefinition(OtherTargetObject.class,
                "countLength", new Class[] {String.class});
        Set set1 = toSet(def1);
        assertTrue(set1.contains(new SecurityConfig("MOCK_INTERFACE")));
        assertTrue(set1.contains(
                new SecurityConfig("MOCK_INTERFACE_METHOD_COUNT_LENGTH")));

        // Confirm MOCK_CLASS_METHOD_COUNT_LENGTH not added, as it's a String (not a ConfigAttribute)
        // Confirm also MOCK_CLASS not added, as we return null for class
        assertEquals(2, set1.size());

        ConfigAttributeDefinition def2 = getConfigAttributeDefinition(OtherTargetObject.class,
                "makeLowerCase", new Class[] {String.class});
        Set set2 = toSet(def2);
        assertTrue(set2.contains(new SecurityConfig("MOCK_INTERFACE")));
        assertTrue(set2.contains(
                new SecurityConfig("MOCK_INTERFACE_METHOD_MAKE_LOWER_CASE")));
        assertTrue(set2.contains(
                new SecurityConfig("MOCK_CLASS_METHOD_MAKE_LOWER_CASE")));

        // Confirm MOCK_CLASS not added, as we return null for class
        assertEquals(3, set2.size());

        ConfigAttributeDefinition def3 = getConfigAttributeDefinition(OtherTargetObject.class,
                "makeUpperCase", new Class[] {String.class});
        Set set3 = toSet(def3);
        assertTrue(set3.contains(new SecurityConfig("MOCK_INTERFACE")));
        assertTrue(set3.contains(
                new SecurityConfig("MOCK_INTERFACE_METHOD_MAKE_UPPER_CASE")));
        assertTrue(set3.contains(new SecurityConfig("RUN_AS"))); // defined against interface

        assertEquals(3, set3.size());
    }

    public void testAttributesForTargetObject() throws Exception {
        ConfigAttributeDefinition def1 = getConfigAttributeDefinition(TargetObject.class,
                "countLength", new Class[] {String.class});
        Set set1 = toSet(def1);
        assertTrue(set1.contains(new SecurityConfig("MOCK_INTERFACE")));
        assertTrue(set1.contains(
                new SecurityConfig("MOCK_INTERFACE_METHOD_COUNT_LENGTH")));

        assertTrue(set1.contains(new SecurityConfig("MOCK_CLASS")));

        // Confirm the MOCK_CLASS_METHOD_COUNT_LENGTH was not added, as it's not a ConfigAttribute
        assertEquals(3, set1.size());

        ConfigAttributeDefinition def2 = getConfigAttributeDefinition(TargetObject.class,
                "makeLowerCase", new Class[] {String.class});
        Set set2 = toSet(def2);
        assertTrue(set2.contains(new SecurityConfig("MOCK_INTERFACE")));
        assertTrue(set2.contains(
                new SecurityConfig("MOCK_INTERFACE_METHOD_MAKE_LOWER_CASE")));
        assertTrue(set2.contains(new SecurityConfig("MOCK_CLASS")));
        assertTrue(set2.contains(
                new SecurityConfig("MOCK_CLASS_METHOD_MAKE_LOWER_CASE")));
        assertEquals(4, set2.size());

        ConfigAttributeDefinition def3 = getConfigAttributeDefinition(TargetObject.class,
                "makeUpperCase", new Class[] {String.class});
        Set set3 = toSet(def3);
        assertTrue(set3.contains(new SecurityConfig("MOCK_INTERFACE")));
        assertTrue(set3.contains(
                new SecurityConfig("MOCK_INTERFACE_METHOD_MAKE_UPPER_CASE")));
        assertTrue(set3.contains(new SecurityConfig("MOCK_CLASS")));
        assertTrue(set3.contains(
                new SecurityConfig("MOCK_CLASS_METHOD_MAKE_UPPER_CASE")));
        assertTrue(set3.contains(new SecurityConfig("RUN_AS")));
        assertEquals(5, set3.size());
    }

    public void testMethodCallWithRunAsReplacement() throws Exception {
        SecureContext context = new SecureContextImpl();
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("Test",
                "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("MOCK_INTERFACE_METHOD_MAKE_UPPER_CASE")});
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
                new GrantedAuthority[] {new GrantedAuthorityImpl("MOCK_INTERFACE_METHOD_MAKE_LOWER_CASE")});
        context.setAuthentication(token);
        ContextHolder.setContext(context);

        ITargetObject target = makeInterceptedTarget();
        String result = target.makeLowerCase("HELLO");

        assertEquals("hello net.sf.acegisecurity.providers.UsernamePasswordAuthenticationToken true",
            result);

        ContextHolder.setContext(null);
    }

    private ConfigAttributeDefinition getConfigAttributeDefinition(
        Class clazz, String methodName, Class[] args) throws Exception {
        final Method method = clazz.getMethod(methodName, args);
        MethodDefinitionAttributes source = new MethodDefinitionAttributes();
        source.setAttributes(new MockAttributes());

        ConfigAttributeDefinition config = source.getAttributes(new MockMethodInvocation() {
                    public Method getMethod() {
                        return method;
                    }
                });

        return config;
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
        p.setProperty(PREFIX + "attributes.class",
            "net.sf.acegisecurity.intercept.method.MockAttributes");

        p.setProperty(PREFIX + "objectDefinitionSource.class",
            "net.sf.acegisecurity.intercept.method.MethodDefinitionAttributes");
        p.setProperty(PREFIX + "objectDefinitionSource.attributes(ref)",
            "attributes");

        p.setProperty(PREFIX + "securityInterceptor.class",
            "net.sf.acegisecurity.intercept.method.MethodSecurityInterceptor");
        p.setProperty(PREFIX + "securityInterceptor.authenticationManager(ref)",
            "authentication");
        p.setProperty(PREFIX + "securityInterceptor.accessDecisionManager(ref)",
            "accessDecision");
        p.setProperty(PREFIX + "securityInterceptor.runAsManager(ref)", "runAs");
        p.setProperty(PREFIX
            + "securityInterceptor.objectDefinitionSource(ref)",
            "objectDefinitionSource");

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

    /**
     * convert a <code>ConfigAttributeDefinition</code> into a set of
     * <code>ConfigAttribute</code>(s)
     *
     * @param def the <code>ConfigAttributeDefinition</code> to cover
     *
     * @return a Set of <code>ConfigAttributes</code>
     */
    private Set toSet(ConfigAttributeDefinition def) {
        Set set = new HashSet();
        Iterator i = def.getConfigAttributes();

        while (i.hasNext()) {
            ConfigAttribute a = (ConfigAttribute) i.next();
            set.add(a);
        }

        return set;
    }
}
