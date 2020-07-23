/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.util;

import java.lang.reflect.Method;

import org.aopalliance.intercept.MethodInvocation;
import org.springframework.aop.framework.Advised;
import org.springframework.aop.support.AopUtils;
import org.springframework.util.Assert;

/**
 * Static utility methods for creating <code>MethodInvocation</code>s usable within Spring
 * Security.
 * <p>
 * All methods of this class return a
 * {@link org.springframework.security.util.SimpleMethodInvocation}.
 *
 * @author Ben Alex
 */
public final class MethodInvocationUtils {

	/**
	 * Generates a <code>MethodInvocation</code> for specified <code>methodName</code> on
	 * the passed object, using the <code>args</code> to locate the method.
	 * @param object the object that will be used to find the relevant <code>Method</code>
	 * @param methodName the name of the method to find
	 * @param args arguments that are required as part of the method signature (can be
	 * empty)
	 * @return a <code>MethodInvocation</code>, or <code>null</code> if there was a
	 * problem
	 */
	public static MethodInvocation create(Object object, String methodName, Object... args) {
		Assert.notNull(object, "Object required");

		Class<?>[] classArgs = null;

		if (args != null) {
			classArgs = new Class<?>[args.length];

			for (int i = 0; i < args.length; i++) {
				classArgs[i] = args[i].getClass();
			}
		}

		// Determine the type that declares the requested method, taking into account
		// proxies
		Class<?> target = AopUtils.getTargetClass(object);
		if (object instanceof Advised) {
			Advised a = (Advised) object;
			if (!a.isProxyTargetClass()) {
				Class<?>[] possibleInterfaces = a.getProxiedInterfaces();
				for (Class<?> possibleInterface : possibleInterfaces) {
					try {
						possibleInterface.getMethod(methodName, classArgs);
						// to get here means no exception happened
						target = possibleInterface;
						break;
					}
					catch (Exception ignored) {
						// try the next one
					}
				}
			}
		}

		return createFromClass(object, target, methodName, classArgs, args);
	}

	/**
	 * Generates a <code>MethodInvocation</code> for the specified <code>methodName</code>
	 * on the passed class.
	 *
	 * If a method with this name, taking no arguments does not exist, it will check
	 * through the declared methods on the class, until one is found matching the supplied
	 * name. If more than one method name matches, an <tt>IllegalArgumentException</tt>
	 * will be raised.
	 * @param clazz the class of object that will be used to find the relevant
	 * <code>Method</code>
	 * @param methodName the name of the method to find
	 * @return a <code>MethodInvocation</code>, or <code>null</code> if there was a
	 * problem
	 */
	public static MethodInvocation createFromClass(Class<?> clazz, String methodName) {
		MethodInvocation mi = createFromClass(null, clazz, methodName, null, null);

		if (mi == null) {
			for (Method m : clazz.getDeclaredMethods()) {
				if (m.getName().equals(methodName)) {
					if (mi != null) {
						throw new IllegalArgumentException(
								"The class " + clazz + " has more than one method named" + " '" + methodName + "'");
					}
					mi = new SimpleMethodInvocation(null, m);
				}
			}
		}

		return mi;
	}

	/**
	 * Generates a <code>MethodInvocation</code> for specified <code>methodName</code> on
	 * the passed class, using the <code>args</code> to locate the method.
	 * @param targetObject the object being invoked
	 * @param clazz the class of object that will be used to find the relevant
	 * <code>Method</code>
	 * @param methodName the name of the method to find
	 * @param classArgs arguments that are required to locate the relevant method
	 * signature
	 * @param args the actual arguments that should be passed to SimpleMethodInvocation
	 * @return a <code>MethodInvocation</code>, or <code>null</code> if there was a
	 * problem
	 */
	public static MethodInvocation createFromClass(Object targetObject, Class<?> clazz, String methodName,
			Class<?>[] classArgs, Object[] args) {
		Assert.notNull(clazz, "Class required");
		Assert.hasText(methodName, "MethodName required");

		Method method;

		try {
			method = clazz.getMethod(methodName, classArgs);
		}
		catch (NoSuchMethodException e) {
			return null;
		}

		return new SimpleMethodInvocation(targetObject, method, args);
	}

}
