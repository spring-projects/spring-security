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

package org.acegisecurity.intercept.method;

import org.acegisecurity.ITargetObject;
import org.acegisecurity.OtherTargetObject;
import org.acegisecurity.SecurityConfig;
import org.acegisecurity.TargetObject;

import org.springframework.metadata.Attributes;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;


/**
 * Used by the {@link MethodDefinitionAttributesTests}.
 *
 * @author Cameron Braid
 * @author Ben Alex
 */
public class MockAttributes implements Attributes {
    //~ Instance fields ========================================================

    List classAttributes = Arrays.asList(new SecurityConfig[] {new SecurityConfig(
                    "MOCK_CLASS")});
    List classMethodAttributesCountLength = Arrays.asList(new String[] {new String(
                    "MOCK_CLASS_METHOD_COUNT_LENGTH")});
    List classMethodAttributesMakeLowerCase = Arrays.asList(new SecurityConfig[] {new SecurityConfig(
                    "MOCK_CLASS_METHOD_MAKE_LOWER_CASE")});
    List classMethodAttributesMakeUpperCase = Arrays.asList(new SecurityConfig[] {new SecurityConfig(
                    "MOCK_CLASS_METHOD_MAKE_UPPER_CASE")});
    List interfaceAttributes = Arrays.asList(new SecurityConfig[] {new SecurityConfig(
                    "MOCK_INTERFACE")});
    List interfaceMethodAttributesCountLength = Arrays.asList(new SecurityConfig[] {new SecurityConfig(
                    "MOCK_INTERFACE_METHOD_COUNT_LENGTH")});
    List interfaceMethodAttributesMakeLowerCase = Arrays.asList(new SecurityConfig[] {new SecurityConfig(
                    "MOCK_INTERFACE_METHOD_MAKE_LOWER_CASE")});
    List interfaceMethodAttributesMakeUpperCase = Arrays.asList(new SecurityConfig[] {new SecurityConfig(
                    "MOCK_INTERFACE_METHOD_MAKE_UPPER_CASE"), new SecurityConfig(
                    "RUN_AS")});

    //~ Methods ================================================================

    public Collection getAttributes(Class clazz) {
        // Emphasise we return null for OtherTargetObject
        if (clazz.equals(OtherTargetObject.class)) {
            return null;
        }

        // interface
        if (clazz.equals(ITargetObject.class)) {
            return interfaceAttributes;
        }

        // class
        if (clazz.equals(TargetObject.class)) {
            return classAttributes;
        }

        return null;
    }

    public Collection getAttributes(Method method) {
        // interface
        if (method.getDeclaringClass().equals(ITargetObject.class)) {
            if (method.getName().equals("countLength")) {
                return interfaceMethodAttributesCountLength;
            }

            if (method.getName().equals("makeLowerCase")) {
                return interfaceMethodAttributesMakeLowerCase;
            }

            if (method.getName().equals("makeUpperCase")) {
                return interfaceMethodAttributesMakeUpperCase;
            }

            if (method.getName().equals("publicMakeLowerCase")) {
                throw new UnsupportedOperationException(
                    "mock support not implemented");
            }
        }

        // class
        if (method.getDeclaringClass().equals(TargetObject.class)) {
            if (method.getName().equals("countLength")) {
                return classMethodAttributesCountLength;
            }

            if (method.getName().equals("makeLowerCase")) {
                return classMethodAttributesMakeLowerCase;
            }

            if (method.getName().equals("makeUpperCase")) {
                return classMethodAttributesMakeUpperCase;
            }

            if (method.getName().equals("publicMakeLowerCase")) {
                throw new UnsupportedOperationException(
                    "mock support not implemented");
            }
        }

        // other target object
        if (method.getDeclaringClass().equals(OtherTargetObject.class)) {
            if (method.getName().equals("countLength")) {
                return classMethodAttributesCountLength;
            }

            if (method.getName().equals("makeLowerCase")) {
                return classMethodAttributesMakeLowerCase;
            }

            if (method.getName().equals("makeUpperCase")) {
                return null; // NB
            }

            if (method.getName().equals("publicMakeLowerCase")) {
                throw new UnsupportedOperationException(
                    "mock support not implemented");
            }
        }

        return null;
    }

    public Collection getAttributes(Class arg0, Class arg1) {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public Collection getAttributes(Field arg0, Class arg1) {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public Collection getAttributes(Field arg0) {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public Collection getAttributes(Method arg0, Class arg1) {
        throw new UnsupportedOperationException("mock method not implemented");
    }
}
