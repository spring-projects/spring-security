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

package org.springframework.security.annotation;

import java.lang.reflect.AccessibleObject;
import java.lang.reflect.Method;

import junit.framework.TestCase;

import org.springframework.security.ConfigAttributeDefinition;
import org.springframework.security.SecurityConfig;
import org.springframework.security.annotation.test.Entity;
import org.springframework.security.annotation.test.OrganisationService;
import org.springframework.security.annotation.test.PersonService;
import org.springframework.security.annotation.test.PersonServiceImpl;
import org.springframework.security.annotation.test.Service;
import org.springframework.security.annotation.test.ServiceImpl;
import org.springframework.security.intercept.method.MethodDefinitionMap;
import org.springframework.security.intercept.method.MethodDefinitionSourceEditor;
import org.aopalliance.intercept.MethodInvocation;


/**
 * Extra tests to demonstrate generics behaviour with <code>MethodDefinitionMap</code>.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class MethodDefinitionSourceEditorTigerTests extends TestCase {
    //~ Constructors ===================================================================================================

    public MethodDefinitionSourceEditorTigerTests() {
        super();
    }

    public MethodDefinitionSourceEditorTigerTests(String arg0) {
        super(arg0);
    }

    //~ Methods ========================================================================================================

    public static void main(String[] args) {
        junit.textui.TestRunner.run(MethodDefinitionSourceEditorTigerTests.class);
    }

    public final void setUp() throws Exception {
        super.setUp();
    }

    public void testConcreteClassInvocationsAlsoReturnDefinitionsAgainstInterface()
        throws Exception {
        MethodDefinitionSourceEditor editor = new MethodDefinitionSourceEditor();
        editor.setAsText(
            "org.springframework.security.annotation.test.Service.makeLower*=ROLE_FROM_INTERFACE\r\norg.springframework.security.annotation.test.Service.makeUpper*=ROLE_FROM_INTERFACE\r\norg.springframework.security.annotation.test.ServiceImpl.makeUpper*=ROLE_FROM_IMPLEMENTATION");

        MethodDefinitionMap map = (MethodDefinitionMap) editor.getValue();
        assertEquals(3, map.getMethodMapSize());

        ConfigAttributeDefinition returnedMakeLower = map.getAttributes(new MockMethodInvocation(Service.class,
                    "makeLowerCase", new Class[] {Entity.class}));
        ConfigAttributeDefinition expectedMakeLower = new ConfigAttributeDefinition();
        expectedMakeLower.addConfigAttribute(new SecurityConfig("ROLE_FROM_INTERFACE"));
        assertEquals(expectedMakeLower, returnedMakeLower);

        ConfigAttributeDefinition returnedMakeUpper = map.getAttributes(new MockMethodInvocation(ServiceImpl.class,
                    "makeUpperCase", new Class[] {Entity.class}));
        ConfigAttributeDefinition expectedMakeUpper = new ConfigAttributeDefinition();
        expectedMakeUpper.addConfigAttribute(new SecurityConfig("ROLE_FROM_IMPLEMENTATION"));
        expectedMakeUpper.addConfigAttribute(new SecurityConfig("ROLE_FROM_INTERFACE"));
        assertEquals(expectedMakeUpper, returnedMakeUpper);
    }

    public void testGenericsSuperclassDeclarationsAreIncludedWhenSubclassesOverride()
        throws Exception {
        MethodDefinitionSourceEditor editor = new MethodDefinitionSourceEditor();
        editor.setAsText(
            "org.springframework.security.annotation.test.Service.makeLower*=ROLE_FROM_INTERFACE\r\norg.springframework.security.annotation.test.Service.makeUpper*=ROLE_FROM_INTERFACE\r\norg.springframework.security.annotation.test.ServiceImpl.makeUpper*=ROLE_FROM_IMPLEMENTATION");

        MethodDefinitionMap map = (MethodDefinitionMap) editor.getValue();
        assertEquals(3, map.getMethodMapSize());

        ConfigAttributeDefinition returnedMakeLower = map.getAttributes(new MockMethodInvocation(PersonService.class,
                    "makeLowerCase", new Class[] {Entity.class}));
        ConfigAttributeDefinition expectedMakeLower = new ConfigAttributeDefinition();
        expectedMakeLower.addConfigAttribute(new SecurityConfig("ROLE_FROM_INTERFACE"));
        assertEquals(expectedMakeLower, returnedMakeLower);

        ConfigAttributeDefinition returnedMakeLower2 = map.getAttributes(new MockMethodInvocation(
                    OrganisationService.class, "makeLowerCase", new Class[] {Entity.class}));
        ConfigAttributeDefinition expectedMakeLower2 = new ConfigAttributeDefinition();
        expectedMakeLower2.addConfigAttribute(new SecurityConfig("ROLE_FROM_INTERFACE"));
        assertEquals(expectedMakeLower2, returnedMakeLower2);

        ConfigAttributeDefinition returnedMakeUpper = map.getAttributes(new MockMethodInvocation(
                    PersonServiceImpl.class, "makeUpperCase", new Class[] {Entity.class}));
        ConfigAttributeDefinition expectedMakeUpper = new ConfigAttributeDefinition();
        expectedMakeUpper.addConfigAttribute(new SecurityConfig("ROLE_FROM_IMPLEMENTATION"));
        expectedMakeUpper.addConfigAttribute(new SecurityConfig("ROLE_FROM_INTERFACE"));
        assertEquals(expectedMakeUpper, returnedMakeUpper);
    }

    //~ Inner Classes ==================================================================================================

    private class MockMethodInvocation implements MethodInvocation {
        Method method;

        private MockMethodInvocation() {
            super();
        }

        public MockMethodInvocation(Class clazz, String methodName, Class[] parameterTypes)
            throws NoSuchMethodException {
            System.out.println(clazz + " " + methodName + " " + parameterTypes[0]);
            method = clazz.getMethod(methodName, parameterTypes);
        }

        public Object[] getArguments() {
            return null;
        }

        public Method getMethod() {
            return method;
        }

        public AccessibleObject getStaticPart() {
            return null;
        }

        public Object getThis() {
            return null;
        }

        public Object proceed() throws Throwable {
            return null;
        }
    }
}
