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

package org.springframework.security.util;

import org.aopalliance.intercept.MethodInvocation;

import org.springframework.util.Assert;

import java.lang.reflect.Method;

import java.util.ArrayList;
import java.util.List;


/**
 * Static utility methods for creating <code>MethodInvocation</code>s usable within Spring Security.
 * <p>All methods of this class return a {@link org.springframework.security.util.SimpleMethodInvocation}.</p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public final class MethodInvocationUtils {
    //~ Constructors ===================================================================================================

    private MethodInvocationUtils() {
    }

    //~ Methods ========================================================================================================

    /**
     * Generates a <code>MethodInvocation</code> for specified <code>methodName</code> on the passed object.
     *
     * @param object the object that will be used to find the relevant <code>Method</code>
     * @param methodName the name of the method to find
     *
     * @return a <code>MethodInvocation</code>, or <code>null</code> if there was a problem
     */
    public static MethodInvocation create(Object object, String methodName) {
        return create(object, methodName, null);
    }

    /**
     * Generates a <code>MethodInvocation</code> for specified <code>methodName</code> on the passed object,
     * using the <code>args</code> to locate the method.
     *
     * @param object the object that will be used to find the relevant <code>Method</code>
     * @param methodName the name of the method to find
     * @param args arguments that are required as part of the method signature
     *
     * @return a <code>MethodInvocation</code>, or <code>null</code> if there was a problem
     */
    public static MethodInvocation create(Object object, String methodName, Object[] args) {
        Assert.notNull(object, "Object required");

        Class[] classArgs = null;

        if (args != null) {
            List list = new ArrayList();

            for (int i = 0; i < args.length; i++) {
                list.add(args[i].getClass());
            }

            classArgs = (Class[]) list.toArray(new Class[] {});
        }

        return createFromClass(object.getClass(), methodName, classArgs, args);
    }

    /**
     * Generates a <code>MethodInvocation</code> for specified <code>methodName</code> on the passed class.
     *
     * @param clazz the class of object that will be used to find the relevant <code>Method</code>
     * @param methodName the name of the method to find
     *
     * @return a <code>MethodInvocation</code>, or <code>null</code> if there was a problem
     */
    public static MethodInvocation createFromClass(Class clazz, String methodName) {
        return createFromClass(clazz, methodName, null, null);
    }

    /**
     * Generates a <code>MethodInvocation</code> for specified <code>methodName</code> on the passed class,
     * using the <code>args</code> to locate the method.
     *
     * @param clazz the class of object that will be used to find the relevant <code>Method</code>
     * @param methodName the name of the method to find
     * @param classArgs arguments that are required to locate the relevant method signature
     * @param args the actual arguments that should be passed to SimpleMethodInvocation
     * @return a <code>MethodInvocation</code>, or <code>null</code> if there was a problem
     */
    public static MethodInvocation createFromClass(Class clazz, String methodName, Class[] classArgs, Object[] args) {
        Assert.notNull(clazz, "Class required");
        Assert.hasText(methodName, "MethodName required");

        Method method;

        try {
            method = clazz.getMethod(methodName, classArgs);
        } catch (Exception e) {
            return null;
        }

        return new SimpleMethodInvocation(method, args);
    }
}
