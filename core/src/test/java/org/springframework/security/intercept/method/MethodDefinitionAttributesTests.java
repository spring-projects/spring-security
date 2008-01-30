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

import junit.framework.TestCase;

import org.springframework.security.ConfigAttribute;
import org.springframework.security.ConfigAttributeDefinition;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.GrantedAuthorityImpl;
import org.springframework.security.ITargetObject;
import org.springframework.security.OtherTargetObject;
import org.springframework.security.SecurityConfig;
import org.springframework.security.TargetObject;

import org.springframework.security.acl.basic.SomeDomain;

import org.springframework.security.context.SecurityContextHolder;

import org.springframework.security.providers.UsernamePasswordAuthenticationToken;

import org.springframework.security.util.SimpleMethodInvocation;

import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;

import java.lang.reflect.Method;

import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;


/**
 * Tests {@link MethodDefinitionAttributes}.
 *
 * @author Cameron Braid
 * @author Ben Alex
 * @version $Id$
 */
public class MethodDefinitionAttributesTests extends TestCase {
    //~ Instance fields ================================================================================================

    ClassPathXmlApplicationContext applicationContext;

    //~ Constructors ===================================================================================================

    public MethodDefinitionAttributesTests(String a) {
        super(a);
    }

    //~ Methods ========================================================================================================


    protected void tearDown() throws Exception {
        super.tearDown();
        SecurityContextHolder.clearContext();
    }

    private ConfigAttributeDefinition getConfigAttributeDefinition(Class clazz, String methodName, Class[] args)
            throws Exception {
        
        final Method method = clazz.getMethod(methodName, args);
        MethodDefinitionAttributes source = new MethodDefinitionAttributes();
        source.setAttributes(new MockAttributes());

        ConfigAttributeDefinition config = source.getAttributes(new SimpleMethodInvocation() {
                    public Method getMethod() {
                        return method;
                    }
                });

        return config;
    }

    private ITargetObject makeInterceptedTarget() {
        ApplicationContext context = new ClassPathXmlApplicationContext(
                "org/springframework/security/intercept/method/applicationContext.xml");

        return (ITargetObject) context.getBean("target");
    }

    public final void setUp() throws Exception {
        super.setUp();
    }

    public void testAttributesForInterfaceTargetObject() throws Exception {
        ConfigAttributeDefinition def1 = getConfigAttributeDefinition(ITargetObject.class, "countLength",
                new Class[] {String.class});
        Set set1 = toSet(def1);
        assertTrue(set1.contains(new SecurityConfig("MOCK_INTERFACE")));
        assertTrue(set1.contains(new SecurityConfig("MOCK_INTERFACE_METHOD_COUNT_LENGTH")));

        ConfigAttributeDefinition def2 = getConfigAttributeDefinition(ITargetObject.class, "makeLowerCase",
                new Class[] {String.class});
        Set set2 = toSet(def2);
        assertTrue(set2.contains(new SecurityConfig("MOCK_INTERFACE")));
        assertTrue(set2.contains(new SecurityConfig("MOCK_INTERFACE_METHOD_MAKE_LOWER_CASE")));

        ConfigAttributeDefinition def3 = getConfigAttributeDefinition(ITargetObject.class, "makeUpperCase",
                new Class[] {String.class});
        Set set3 = toSet(def3);
        assertTrue(set3.contains(new SecurityConfig("MOCK_INTERFACE")));
        assertTrue(set3.contains(new SecurityConfig("MOCK_INTERFACE_METHOD_MAKE_UPPER_CASE")));
    }

    public void testAttributesForOtherTargetObject() throws Exception {
        ConfigAttributeDefinition def1 = getConfigAttributeDefinition(OtherTargetObject.class, "countLength",
                new Class[] {String.class});
        Set set1 = toSet(def1);
        assertTrue(set1.contains(new SecurityConfig("MOCK_INTERFACE")));
        assertTrue(set1.contains(new SecurityConfig("MOCK_INTERFACE_METHOD_COUNT_LENGTH")));

        // Confirm MOCK_CLASS_METHOD_COUNT_LENGTH not added, as it's a String (not a ConfigAttribute)
        // Confirm also MOCK_CLASS not added, as we return null for class
        assertEquals(2, set1.size());

        ConfigAttributeDefinition def2 = getConfigAttributeDefinition(OtherTargetObject.class, "makeLowerCase",
                new Class[] {String.class});
        Set set2 = toSet(def2);
        assertTrue(set2.contains(new SecurityConfig("MOCK_INTERFACE")));
        assertTrue(set2.contains(new SecurityConfig("MOCK_INTERFACE_METHOD_MAKE_LOWER_CASE")));
        assertTrue(set2.contains(new SecurityConfig("MOCK_CLASS_METHOD_MAKE_LOWER_CASE")));

        // Confirm MOCK_CLASS not added, as we return null for class
        assertEquals(3, set2.size());

        ConfigAttributeDefinition def3 = getConfigAttributeDefinition(OtherTargetObject.class, "makeUpperCase",
                new Class[] {String.class});
        Set set3 = toSet(def3);
        assertTrue(set3.contains(new SecurityConfig("MOCK_INTERFACE")));
        assertTrue(set3.contains(new SecurityConfig("MOCK_INTERFACE_METHOD_MAKE_UPPER_CASE")));
        assertTrue(set3.contains(new SecurityConfig("RUN_AS"))); // defined against interface

        assertEquals(3, set3.size());
    }

    public void testAttributesForTargetObject() throws Exception {
        ConfigAttributeDefinition def1 = getConfigAttributeDefinition(TargetObject.class, "countLength",
                new Class[] {String.class});
        Set set1 = toSet(def1);
        assertTrue(set1.contains(new SecurityConfig("MOCK_INTERFACE")));
        assertTrue(set1.contains(new SecurityConfig("MOCK_INTERFACE_METHOD_COUNT_LENGTH")));

        assertTrue(set1.contains(new SecurityConfig("MOCK_CLASS")));

        // Confirm the MOCK_CLASS_METHOD_COUNT_LENGTH was not added, as it's not a ConfigAttribute
        assertEquals(3, set1.size());

        ConfigAttributeDefinition def2 = getConfigAttributeDefinition(TargetObject.class, "makeLowerCase",
                new Class[] {String.class});
        Set set2 = toSet(def2);
        assertTrue(set2.contains(new SecurityConfig("MOCK_INTERFACE")));
        assertTrue(set2.contains(new SecurityConfig("MOCK_INTERFACE_METHOD_MAKE_LOWER_CASE")));
        assertTrue(set2.contains(new SecurityConfig("MOCK_CLASS")));
        assertTrue(set2.contains(new SecurityConfig("MOCK_CLASS_METHOD_MAKE_LOWER_CASE")));
        assertEquals(4, set2.size());

        ConfigAttributeDefinition def3 = getConfigAttributeDefinition(TargetObject.class, "makeUpperCase",
                new Class[] {String.class});
        Set set3 = toSet(def3);
        assertTrue(set3.contains(new SecurityConfig("MOCK_INTERFACE")));
        assertTrue(set3.contains(new SecurityConfig("MOCK_INTERFACE_METHOD_MAKE_UPPER_CASE")));
        assertTrue(set3.contains(new SecurityConfig("MOCK_CLASS")));
        assertTrue(set3.contains(new SecurityConfig("MOCK_CLASS_METHOD_MAKE_UPPER_CASE")));
        assertTrue(set3.contains(new SecurityConfig("RUN_AS")));
        assertEquals(5, set3.size());
    }

    public void testMethodCallWithRunAsReplacement() throws Exception {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("Test", "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("MOCK_INTERFACE_METHOD_MAKE_UPPER_CASE")});
        SecurityContextHolder.getContext().setAuthentication(token);

        ITargetObject target = makeInterceptedTarget();
        String result = target.makeUpperCase("hello");
        assertEquals("HELLO org.springframework.security.MockRunAsAuthenticationToken true", result);
    }

    public void testMethodCallWithoutRunAsReplacement() throws Exception {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("Test", "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("MOCK_INTERFACE_METHOD_MAKE_LOWER_CASE")});
        SecurityContextHolder.getContext().setAuthentication(token);

        ITargetObject target = makeInterceptedTarget();
        String result = target.makeLowerCase("HELLO");

        assertEquals("hello org.springframework.security.providers.UsernamePasswordAuthenticationToken true", result);
    }

    public void testNullReturnedIfZeroAttributesDefinedForMethodInvocation()
        throws Exception {
        // SomeDomain is not defined in the MockAttributes()
        // (which getConfigAttributeDefinition refers to)
        ConfigAttributeDefinition def = getConfigAttributeDefinition(SomeDomain.class, "getId", null);
        assertNull(def);
    }

    /**
     * convert a <code>ConfigAttributeDefinition</code> into a set of <code>ConfigAttribute</code>(s)
     *
     * @param def the <code>ConfigAttributeDefinition</code> to cover
     *
     * @return a Set of <code>ConfigAttributes</code>
     */
    private Set toSet(ConfigAttributeDefinition def) {
        Set set = new HashSet();
        Iterator i = def.getConfigAttributes().iterator();

        while (i.hasNext()) {
            ConfigAttribute a = (ConfigAttribute) i.next();
            set.add(a);
        }

        return set;
    }
}
