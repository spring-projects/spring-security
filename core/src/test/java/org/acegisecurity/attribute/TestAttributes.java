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

package net.sf.acegisecurity.attribute;

import net.sf.acegisecurity.SecurityConfig;

import java.lang.reflect.Method;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;


/**
 * DOCUMENT ME!
 *
 * @author CameronBraid
 */
public class TestAttributes extends MockAttributes {
    //~ Instance fields ========================================================

    List classAttributes = Arrays.asList(new SecurityConfig[] {new SecurityConfig(
                    "ROLE_CLASS")});
    List classMethodAttributes = Arrays.asList(new SecurityConfig[] {new SecurityConfig(
                    "ROLE_CLASS_METHOD")});
    List intrefaceAttributes = Arrays.asList(new SecurityConfig[] {new SecurityConfig(
                    "ROLE_INTERFACE")});
    List intrefaceMethodAttributes = Arrays.asList(new SecurityConfig[] {new SecurityConfig(
                    "ROLE_INTERFACE_METHOD")});

    //~ Methods ================================================================

    public Collection getAttributes(Class clazz) {
        // interface
        if (clazz.equals(TestServiceImpl.class)) {
            return classAttributes;
        }

        // class
        if (clazz.equals(TestService.class)) {
            return intrefaceAttributes;
        }

        return null;
    }

    public Collection getAttributes(Method method) {
        // interface
        if (method.getDeclaringClass().equals(TestService.class)) {
            return intrefaceMethodAttributes;
        }

        // class
        if (method.getDeclaringClass().equals(TestServiceImpl.class)) {
            return classMethodAttributes;
        }

        return null;
    }
}
