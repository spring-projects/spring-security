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

import net.sf.acegisecurity.ConfigAttributeDefinition;
import net.sf.acegisecurity.SecurityConfig;
import net.sf.acegisecurity.TargetObject;

import org.aopalliance.intercept.MethodInvocation;

import java.lang.reflect.AccessibleObject;
import java.lang.reflect.Method;

import java.util.Iterator;


/**
 * Tests {@link MethodDefinitionSourceEditor} and its asociated {@link
 * MethodDefinitionMap}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class MethodDefinitionSourceEditorTests extends TestCase {
    //~ Constructors ===========================================================

    public MethodDefinitionSourceEditorTests() {
        super();
    }

    public MethodDefinitionSourceEditorTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(MethodDefinitionSourceEditorTests.class);
    }

    public void testClassNameNotFoundResultsInException() {
        MethodDefinitionSourceEditor editor = new MethodDefinitionSourceEditor();

        try {
            editor.setAsText("net.sf.acegisecurity.DOES_NOT_EXIST_NAME=FOO,BAR");
            fail("Should have given IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testClassNameNotInProperFormatResultsInException() {
        MethodDefinitionSourceEditor editor = new MethodDefinitionSourceEditor();

        try {
            editor.setAsText("DOES_NOT_EXIST_NAME=FOO,BAR");
            fail("Should have given IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testClassNameValidButMethodNameInvalidResultsInException() {
        MethodDefinitionSourceEditor editor = new MethodDefinitionSourceEditor();

        try {
            editor.setAsText(
                "net.sf.acegisecurity.TargetObject.INVALID_METHOD=FOO,BAR");
            fail("Should have given IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testEmptyStringReturnsEmptyMap() {
        MethodDefinitionSourceEditor editor = new MethodDefinitionSourceEditor();
        editor.setAsText("");

        MethodDefinitionMap map = (MethodDefinitionMap) editor.getValue();
        assertEquals(0, map.getMethodMapSize());
    }

    public void testIterator() {
        MethodDefinitionSourceEditor editor = new MethodDefinitionSourceEditor();
        editor.setAsText(
            "net.sf.acegisecurity.TargetObject.countLength=ROLE_ONE,ROLE_TWO,RUN_AS_ENTRY\r\nnet.sf.acegisecurity.TargetObject.make*=ROLE_NINE,ROLE_SUPERVISOR");

        MethodDefinitionMap map = (MethodDefinitionMap) editor.getValue();
        Iterator iter = map.getConfigAttributeDefinitions();
        int counter = 0;

        while (iter.hasNext()) {
            iter.next();
            counter++;
        }

        assertEquals(3, counter);
    }

    public void testMultiMethodParsing() {
        MethodDefinitionSourceEditor editor = new MethodDefinitionSourceEditor();
        editor.setAsText(
            "net.sf.acegisecurity.TargetObject.countLength=ROLE_ONE,ROLE_TWO,RUN_AS_ENTRY\r\nnet.sf.acegisecurity.TargetObject.make*=ROLE_NINE,ROLE_SUPERVISOR");

        MethodDefinitionMap map = (MethodDefinitionMap) editor.getValue();
        assertEquals(3, map.getMethodMapSize());
    }

    public void testMultiMethodParsingWhereLaterMethodsOverrideEarlierMethods()
        throws Exception {
        MethodDefinitionSourceEditor editor = new MethodDefinitionSourceEditor();
        editor.setAsText(
            "net.sf.acegisecurity.TargetObject.*=ROLE_GENERAL\r\nnet.sf.acegisecurity.TargetObject.makeLower*=ROLE_LOWER\r\nnet.sf.acegisecurity.TargetObject.make*=ROLE_MAKE\r\nnet.sf.acegisecurity.TargetObject.makeUpper*=ROLE_UPPER");

        MethodDefinitionMap map = (MethodDefinitionMap) editor.getValue();
        assertEquals(4, map.getMethodMapSize());

        ConfigAttributeDefinition returnedMakeLower = map.getAttributes(new MockMethodInvocation(
                    TargetObject.class, "makeLowerCase",
                    new Class[] {String.class}));
        ConfigAttributeDefinition expectedMakeLower = new ConfigAttributeDefinition();
        expectedMakeLower.addConfigAttribute(new SecurityConfig("ROLE_LOWER"));
        assertEquals(expectedMakeLower, returnedMakeLower);

        ConfigAttributeDefinition returnedMakeUpper = map.getAttributes(new MockMethodInvocation(
                    TargetObject.class, "makeUpperCase",
                    new Class[] {String.class}));
        ConfigAttributeDefinition expectedMakeUpper = new ConfigAttributeDefinition();
        expectedMakeUpper.addConfigAttribute(new SecurityConfig("ROLE_UPPER"));
        assertEquals(expectedMakeUpper, returnedMakeUpper);

        ConfigAttributeDefinition returnedCountLength = map.getAttributes(new MockMethodInvocation(
                    TargetObject.class, "countLength",
                    new Class[] {String.class}));
        ConfigAttributeDefinition expectedCountLength = new ConfigAttributeDefinition();
        expectedCountLength.addConfigAttribute(new SecurityConfig(
                "ROLE_GENERAL"));
        assertEquals(expectedCountLength, returnedCountLength);
    }

    public void testNullReturnsEmptyMap() {
        MethodDefinitionSourceEditor editor = new MethodDefinitionSourceEditor();
        editor.setAsText(null);

        MethodDefinitionMap map = (MethodDefinitionMap) editor.getValue();
        assertEquals(0, map.getMethodMapSize());
    }

    public void testSingleMethodParsing() throws Exception {
        MethodDefinitionSourceEditor editor = new MethodDefinitionSourceEditor();
        editor.setAsText(
            "net.sf.acegisecurity.TargetObject.countLength=ROLE_ONE,ROLE_TWO,RUN_AS_ENTRY");

        MethodDefinitionMap map = (MethodDefinitionMap) editor.getValue();

        ConfigAttributeDefinition returnedCountLength = map.getAttributes(new MockMethodInvocation(
                    TargetObject.class, "countLength",
                    new Class[] {String.class}));
        ConfigAttributeDefinition expectedCountLength = new ConfigAttributeDefinition();
        expectedCountLength.addConfigAttribute(new SecurityConfig("ROLE_ONE"));
        expectedCountLength.addConfigAttribute(new SecurityConfig("ROLE_TWO"));
        expectedCountLength.addConfigAttribute(new SecurityConfig(
                "RUN_AS_ENTRY"));
        assertEquals(expectedCountLength, returnedCountLength);
    }

    //~ Inner Classes ==========================================================

    private class MockMethodInvocation implements MethodInvocation {
        Method method;

        public MockMethodInvocation(Class clazz, String methodName,
            Class[] parameterTypes) throws NoSuchMethodException {
            method = clazz.getMethod(methodName, parameterTypes);
        }

        private MockMethodInvocation() {
            super();
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
