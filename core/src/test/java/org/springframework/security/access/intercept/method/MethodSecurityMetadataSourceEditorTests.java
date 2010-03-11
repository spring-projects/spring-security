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

package org.springframework.security.access.intercept.method;

import java.lang.reflect.AccessibleObject;
import java.lang.reflect.Method;
import java.util.Collection;
import java.util.List;

import junit.framework.TestCase;

import org.aopalliance.intercept.MethodInvocation;
import org.springframework.security.ITargetObject;
import org.springframework.security.OtherTargetObject;
import org.springframework.security.TargetObject;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.method.MapBasedMethodSecurityMetadataSource;
import org.springframework.security.access.method.MethodSecurityMetadataSourceEditor;


/**
 * Tests {@link MethodSecurityMetadataSourceEditor} and its associated {@link MapBasedMethodSecurityMetadataSource}.
 *
 * @author Ben Alex
 */
@SuppressWarnings("deprecation")
public class MethodSecurityMetadataSourceEditorTests extends TestCase {
    //~ Methods ========================================================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public void testClassNameNotFoundResultsInException() {
        MethodSecurityMetadataSourceEditor editor = new MethodSecurityMetadataSourceEditor();

        try {
            editor.setAsText("org.springframework.security.DOES_NOT_EXIST_NAME=FOO,BAR");
            fail("Should have given IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testClassNameNotInProperFormatResultsInException() {
        MethodSecurityMetadataSourceEditor editor = new MethodSecurityMetadataSourceEditor();

        try {
            editor.setAsText("DOES_NOT_EXIST_NAME=FOO,BAR");
            fail("Should have given IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testClassNameValidButMethodNameInvalidResultsInException() {
        MethodSecurityMetadataSourceEditor editor = new MethodSecurityMetadataSourceEditor();

        try {
            editor.setAsText("org.springframework.security.TargetObject.INVALID_METHOD=FOO,BAR");
            fail("Should have given IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testConcreteClassInvocationsAlsoReturnDefinitionsAgainstInterface() throws Exception {
        MethodSecurityMetadataSourceEditor editor = new MethodSecurityMetadataSourceEditor();
        editor.setAsText(
            "org.springframework.security.ITargetObject.computeHashCode*=ROLE_FROM_INTERFACE\r\n" +
            "org.springframework.security.ITargetObject.makeLower*=ROLE_FROM_INTERFACE\r\n" +
            "org.springframework.security.ITargetObject.makeUpper*=ROLE_FROM_INTERFACE\r\n" +
            "org.springframework.security.TargetObject.computeHashCode*=ROLE_FROM_TO\r\n" +
            "org.springframework.security.OtherTargetObject.computeHashCode*=ROLE_FROM_OTO\r\n" +
            "org.springframework.security.OtherTargetObject.makeUpper*=ROLE_FROM_IMPLEMENTATION");

        MapBasedMethodSecurityMetadataSource map = (MapBasedMethodSecurityMetadataSource) editor.getValue();
        assertEquals(6, map.getMethodMapSize());

        Collection<ConfigAttribute> returnedMakeLower = map.getAttributes(new MockMethodInvocation(ITargetObject.class, "makeLowerCase", new Class[] {String.class}, new OtherTargetObject()));
        List<ConfigAttribute> expectedMakeLower = SecurityConfig.createList("ROLE_FROM_INTERFACE");
        assertEquals(expectedMakeLower, returnedMakeLower);

        Collection<ConfigAttribute> returnedMakeUpper = map.getAttributes(new MockMethodInvocation(ITargetObject.class, "makeUpperCase", new Class[] {String.class}, new OtherTargetObject()));
        List<ConfigAttribute> expectedMakeUpper = SecurityConfig.createList("ROLE_FROM_IMPLEMENTATION");
        assertEquals(expectedMakeUpper, returnedMakeUpper);

        Collection<ConfigAttribute> returnedComputeHashCode = map.getAttributes(new MockMethodInvocation(ITargetObject.class, "computeHashCode", new Class[] {String.class}, new OtherTargetObject()));
        List<ConfigAttribute> expectedComputeHashCode = SecurityConfig.createList("ROLE_FROM_OTO");
        assertEquals(expectedComputeHashCode, returnedComputeHashCode);

        returnedComputeHashCode = map.getAttributes(new MockMethodInvocation(ITargetObject.class, "computeHashCode", new Class[] {String.class}, new TargetObject()));
        expectedComputeHashCode = SecurityConfig.createList("ROLE_FROM_TO");
        assertEquals(expectedComputeHashCode, returnedComputeHashCode);
    }

    public void testEmptyStringReturnsEmptyMap() {
        MethodSecurityMetadataSourceEditor editor = new MethodSecurityMetadataSourceEditor();
        editor.setAsText("");

        MapBasedMethodSecurityMetadataSource map = (MapBasedMethodSecurityMetadataSource) editor.getValue();
        assertEquals(0, map.getMethodMapSize());
    }

    public void testIterator() {
        MethodSecurityMetadataSourceEditor editor = new MethodSecurityMetadataSourceEditor();
        editor.setAsText(
            "org.springframework.security.TargetObject.countLength=ROLE_ONE,ROLE_TWO,RUN_AS_ENTRY\r\norg.springframework.security.TargetObject.make*=ROLE_NINE,ROLE_SUPERVISOR");

        MapBasedMethodSecurityMetadataSource map = (MapBasedMethodSecurityMetadataSource) editor.getValue();

        assertEquals(5, map.getAllConfigAttributes().size());
    }

    public void testMultiMethodParsing() {
        MethodSecurityMetadataSourceEditor editor = new MethodSecurityMetadataSourceEditor();
        editor.setAsText(
            "org.springframework.security.TargetObject.countLength=ROLE_ONE,ROLE_TWO,RUN_AS_ENTRY\r\norg.springframework.security.TargetObject.make*=ROLE_NINE,ROLE_SUPERVISOR");

        MapBasedMethodSecurityMetadataSource map = (MapBasedMethodSecurityMetadataSource) editor.getValue();
        assertEquals(3, map.getMethodMapSize());
    }

    public void testMultiMethodParsingWhereLaterMethodsOverrideEarlierMethods() throws Exception {
        MethodSecurityMetadataSourceEditor editor = new MethodSecurityMetadataSourceEditor();
        editor.setAsText(
            "org.springframework.security.TargetObject.*=ROLE_GENERAL\r\norg.springframework.security.TargetObject.makeLower*=ROLE_LOWER\r\norg.springframework.security.TargetObject.make*=ROLE_MAKE\r\norg.springframework.security.TargetObject.makeUpper*=ROLE_UPPER");

        MapBasedMethodSecurityMetadataSource map = (MapBasedMethodSecurityMetadataSource) editor.getValue();
        assertEquals(14, map.getMethodMapSize());

        Collection<ConfigAttribute> returnedMakeLower = map.getAttributes(new MockMethodInvocation(ITargetObject.class,
                    "makeLowerCase", new Class[] {String.class}, new TargetObject()));
        List<ConfigAttribute> expectedMakeLower = SecurityConfig.createList("ROLE_LOWER");
        assertEquals(expectedMakeLower, returnedMakeLower);

        Collection<ConfigAttribute> returnedMakeUpper = map.getAttributes(new MockMethodInvocation(ITargetObject.class,
                    "makeUpperCase", new Class[] {String.class}, new TargetObject()));
        List<ConfigAttribute> expectedMakeUpper = SecurityConfig.createList("ROLE_UPPER");
        assertEquals(expectedMakeUpper, returnedMakeUpper);

        Collection<ConfigAttribute> returnedCountLength = map.getAttributes(new MockMethodInvocation(ITargetObject.class,
                    "countLength", new Class[] {String.class}, new TargetObject()));
        List<ConfigAttribute> expectedCountLength = SecurityConfig.createList("ROLE_GENERAL");
        assertEquals(expectedCountLength, returnedCountLength);
    }

    public void testNullIsReturnedByMethodSecurityMetadataSourceWhenMethodInvocationNotDefined() throws Exception {
        MethodSecurityMetadataSourceEditor editor = new MethodSecurityMetadataSourceEditor();
        editor.setAsText("org.springframework.security.TargetObject.countLength=ROLE_ONE,ROLE_TWO,RUN_AS_ENTRY");

        MapBasedMethodSecurityMetadataSource map = (MapBasedMethodSecurityMetadataSource) editor.getValue();

        Collection<ConfigAttribute> configAttributeDefinition = map.getAttributes(new MockMethodInvocation(
                    ITargetObject.class, "makeLowerCase", new Class[] {String.class}, new TargetObject()));
        assertNull(configAttributeDefinition);
    }

    public void testNullReturnsEmptyMap() {
        MethodSecurityMetadataSourceEditor editor = new MethodSecurityMetadataSourceEditor();
        editor.setAsText(null);

        MapBasedMethodSecurityMetadataSource map = (MapBasedMethodSecurityMetadataSource) editor.getValue();
        assertEquals(0, map.getMethodMapSize());
    }

    public void testSingleMethodParsing() throws Exception {
        MethodSecurityMetadataSourceEditor editor = new MethodSecurityMetadataSourceEditor();
        editor.setAsText("org.springframework.security.TargetObject.countLength=ROLE_ONE,ROLE_TWO,RUN_AS_ENTRY");

        MapBasedMethodSecurityMetadataSource map = (MapBasedMethodSecurityMetadataSource) editor.getValue();

        Collection<ConfigAttribute> returnedCountLength = map.getAttributes(new MockMethodInvocation(ITargetObject.class,
                    "countLength", new Class[] {String.class}, new TargetObject()));
        assertEquals(SecurityConfig.createList("ROLE_ONE", "ROLE_TWO", "RUN_AS_ENTRY"), returnedCountLength);
    }

    //~ Inner Classes ==================================================================================================

    private class MockMethodInvocation implements MethodInvocation {
        private Method method;
        private Object targetObject;

        public MockMethodInvocation(Class<?> clazz, String methodName, Class<?>[] parameterTypes, Object targetObject)
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
