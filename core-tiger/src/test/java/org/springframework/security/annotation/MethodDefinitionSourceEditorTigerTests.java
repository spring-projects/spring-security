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

import org.aopalliance.intercept.MethodInvocation;
import org.springframework.security.ConfigAttributeDefinition;
import org.springframework.security.annotation.test.Entity;
import org.springframework.security.annotation.test.PersonServiceImpl;
import org.springframework.security.annotation.test.Service;
import org.springframework.security.intercept.method.MapBasedMethodDefinitionSource;
import org.springframework.security.intercept.method.MethodDefinitionSourceEditor;


/**
 * Extra tests to demonstrate generics behaviour with <code>MapBasedMethodDefinitionSource</code>.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class MethodDefinitionSourceEditorTigerTests extends TestCase {
    //~ Methods ========================================================================================================

    public void testConcreteClassInvocations() throws Exception {
        MethodDefinitionSourceEditor editor = new MethodDefinitionSourceEditor();
        editor.setAsText(
                "org.springframework.security.annotation.test.Service.makeLower*=ROLE_FROM_INTERFACE\r\n" +
                "org.springframework.security.annotation.test.Service.makeUpper*=ROLE_FROM_INTERFACE\r\n" +
                "org.springframework.security.annotation.test.ServiceImpl.makeUpper*=ROLE_FROM_IMPLEMENTATION");

        MapBasedMethodDefinitionSource map = (MapBasedMethodDefinitionSource) editor.getValue();
        assertEquals(3, map.getMethodMapSize());

        ConfigAttributeDefinition returnedMakeLower = map.getAttributes(new MockMethodInvocation(Service.class,
                "makeLowerCase", new Class[]{Entity.class}, new PersonServiceImpl()));
        ConfigAttributeDefinition expectedMakeLower = new ConfigAttributeDefinition("ROLE_FROM_INTERFACE");
        assertEquals(expectedMakeLower, returnedMakeLower);

        ConfigAttributeDefinition returnedMakeUpper = map.getAttributes(new MockMethodInvocation(Service.class,
                "makeUpperCase", new Class[]{Entity.class}, new PersonServiceImpl()));
        ConfigAttributeDefinition expectedMakeUpper = new ConfigAttributeDefinition(new String[]{"ROLE_FROM_IMPLEMENTATION"});
        assertEquals(expectedMakeUpper, returnedMakeUpper);
    }

    public void testBridgeMethodResolution() throws Exception {
        MethodDefinitionSourceEditor editor = new MethodDefinitionSourceEditor();
        editor.setAsText(
                "org.springframework.security.annotation.test.PersonService.makeUpper*=ROLE_FROM_INTERFACE\r\n" +
                "org.springframework.security.annotation.test.ServiceImpl.makeUpper*=ROLE_FROM_ABSTRACT\r\n" +
        		"org.springframework.security.annotation.test.PersonServiceImpl.makeUpper*=ROLE_FROM_PSI");

        MapBasedMethodDefinitionSource map = (MapBasedMethodDefinitionSource) editor.getValue();
        assertEquals(3, map.getMethodMapSize());

        ConfigAttributeDefinition returnedMakeUpper = map.getAttributes(new MockMethodInvocation(Service.class,
                "makeUpperCase", new Class[]{Entity.class}, new PersonServiceImpl()));
        ConfigAttributeDefinition expectedMakeUpper = new ConfigAttributeDefinition(new String[]{"ROLE_FROM_PSI"});
        assertEquals(expectedMakeUpper, returnedMakeUpper);
    }

    //~ Inner Classes ==================================================================================================

    private class MockMethodInvocation implements MethodInvocation {
        private Method method;
        private Object targetObject;

        public MockMethodInvocation(Class clazz, String methodName, Class[] parameterTypes, Object targetObject)
            throws NoSuchMethodException {
            this.method = clazz.getMethod(methodName, parameterTypes);
            this.targetObject = targetObject;
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
            return targetObject;
        }

        public Object proceed() throws Throwable {
            return null;
        }
    }

}
