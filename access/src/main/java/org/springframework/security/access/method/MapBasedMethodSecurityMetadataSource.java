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

package org.springframework.security.access.method;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.jspecify.annotations.NullUnmarked;
import org.jspecify.annotations.Nullable;

import org.springframework.beans.factory.BeanClassLoaderAware;
import org.springframework.core.log.LogMessage;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.util.Assert;
import org.springframework.util.ClassUtils;

/**
 * Stores a list of <tt>ConfigAttribute</tt>s for a method or class signature.
 *
 * <p>
 * This class is the preferred implementation of {@link MethodSecurityMetadataSource} for
 * XML-based definition of method security metadata. To assist in XML-based definition,
 * wildcard support is provided.
 * </p>
 *
 * @author Ben Alex
 * @since 2.0
 * @deprecated Use the {@code use-authorization-manager} attribute for
 * {@code <method-security>} and {@code <intercept-methods>} instead or use
 * annotation-based or {@link AuthorizationManager}-based authorization
 */
@NullUnmarked
@Deprecated
public class MapBasedMethodSecurityMetadataSource extends AbstractFallbackMethodSecurityMetadataSource
		implements BeanClassLoaderAware {

	@SuppressWarnings("NullAway")
	private @Nullable ClassLoader beanClassLoader = ClassUtils.getDefaultClassLoader();

	/**
	 * Map from RegisteredMethod to ConfigAttribute list
	 */
	protected final Map<RegisteredMethod, List<ConfigAttribute>> methodMap = new HashMap<>();

	/**
	 * Map from RegisteredMethod to name pattern used for registration
	 */
	private final Map<RegisteredMethod, String> nameMap = new HashMap<>();

	public MapBasedMethodSecurityMetadataSource() {
	}

	/**
	 * Creates the <tt>MapBasedMethodSecurityMetadataSource</tt> from a
	 * @param methodMap map of method names to <tt>ConfigAttribute</tt>s.
	 */
	public MapBasedMethodSecurityMetadataSource(Map<String, List<ConfigAttribute>> methodMap) {
		for (Map.Entry<String, List<ConfigAttribute>> entry : methodMap.entrySet()) {
			addSecureMethod(entry.getKey(), entry.getValue());
		}
	}

	/**
	 * Implementation does not support class-level attributes.
	 */
	@Override
	protected @Nullable Collection<ConfigAttribute> findAttributes(Class<?> clazz) {
		return null;
	}

	/**
	 * Will walk the method inheritance tree to find the most specific declaration
	 * applicable.
	 */
	@Override
	protected @Nullable Collection<ConfigAttribute> findAttributes(Method method, Class<?> targetClass) {
		if (targetClass == null) {
			return null;
		}
		return findAttributesSpecifiedAgainst(method, targetClass);
	}

	private @Nullable List<ConfigAttribute> findAttributesSpecifiedAgainst(Method method, Class<?> clazz) {
		RegisteredMethod registeredMethod = new RegisteredMethod(method, clazz);
		if (this.methodMap.containsKey(registeredMethod)) {
			return this.methodMap.get(registeredMethod);
		}
		// Search superclass
		if (clazz.getSuperclass() != null) {
			return findAttributesSpecifiedAgainst(method, clazz.getSuperclass());
		}
		return null;
	}

	/**
	 * Add configuration attributes for a secure method. Method names can end or start
	 * with <code>*</code> for matching multiple methods.
	 * @param name type and method name, separated by a dot
	 * @param attr the security attributes associated with the method
	 */
	private void addSecureMethod(String name, List<ConfigAttribute> attr) {
		int lastDotIndex = name.lastIndexOf(".");
		Assert.isTrue(lastDotIndex != -1, () -> "'" + name + "' is not a valid method name: format is FQN.methodName");
		String methodName = name.substring(lastDotIndex + 1);
		Assert.hasText(methodName, () -> "Method not found for '" + name + "'");
		String typeName = name.substring(0, lastDotIndex);
		Class<?> type = ClassUtils.resolveClassName(typeName, this.beanClassLoader);
		addSecureMethod(type, methodName, attr);
	}

	/**
	 * Add configuration attributes for a secure method. Mapped method names can end or
	 * start with <code>*</code> for matching multiple methods.
	 * @param javaType target interface or class the security configuration attribute
	 * applies to
	 * @param mappedName mapped method name, which the javaType has declared or inherited
	 * @param attr required authorities associated with the method
	 */
	public void addSecureMethod(Class<?> javaType, String mappedName, List<ConfigAttribute> attr) {
		String name = javaType.getName() + '.' + mappedName;
		this.logger.debug(LogMessage.format("Request to add secure method [%s] with attributes [%s]", name, attr));
		Method[] methods = javaType.getMethods();
		List<Method> matchingMethods = new ArrayList<>();
		for (Method method : methods) {
			if (method.getName().equals(mappedName) || isMatch(method.getName(), mappedName)) {
				matchingMethods.add(method);
			}
		}
		Assert.notEmpty(matchingMethods, () -> "Couldn't find method '" + mappedName + "' on '" + javaType + "'");
		registerAllMatchingMethods(javaType, attr, name, matchingMethods);
	}

	private void registerAllMatchingMethods(Class<?> javaType, List<ConfigAttribute> attr, String name,
			List<Method> matchingMethods) {
		for (Method method : matchingMethods) {
			RegisteredMethod registeredMethod = new RegisteredMethod(method, javaType);
			String regMethodName = this.nameMap.get(registeredMethod);
			if ((regMethodName == null) || (!regMethodName.equals(name) && (regMethodName.length() <= name.length()))) {
				// no already registered method name, or more specific
				// method name specification (now) -> (re-)register method
				if (regMethodName != null) {
					this.logger.debug(LogMessage.format(
							"Replacing attributes for secure method [%s]: current name [%s] is more specific than [%s]",
							method, name, regMethodName));
				}
				this.nameMap.put(registeredMethod, name);
				addSecureMethod(registeredMethod, attr);
			}
			else {
				this.logger.debug(LogMessage.format(
						"Keeping attributes for secure method [%s]: current name [%s] is not more specific than [%s]",
						method, name, regMethodName));
			}
		}
	}

	/**
	 * Adds configuration attributes for a specific method, for example where the method
	 * has been matched using a pointcut expression. If a match already exists in the map
	 * for the method, then the existing match will be retained, so that if this method is
	 * called for a more general pointcut it will not override a more specific one which
	 * has already been added.
	 * <p>
	 * This method should only be called during initialization of the {@code BeanFactory}.
	 */
	public void addSecureMethod(Class<?> javaType, Method method, List<ConfigAttribute> attr) {
		RegisteredMethod key = new RegisteredMethod(method, javaType);
		if (this.methodMap.containsKey(key)) {
			this.logger.debug(LogMessage.format("Method [%s] is already registered with attributes [%s]", method,
					this.methodMap.get(key)));
			return;
		}
		this.methodMap.put(key, attr);
	}

	/**
	 * Add configuration attributes for a secure method.
	 * @param method the method to be secured
	 * @param attr required authorities associated with the method
	 */
	private void addSecureMethod(RegisteredMethod method, List<ConfigAttribute> attr) {
		Assert.notNull(method, "RegisteredMethod required");
		Assert.notNull(attr, "Configuration attribute required");
		this.logger.info(LogMessage.format("Adding secure method [%s] with attributes [%s]", method, attr));
		this.methodMap.put(method, attr);
	}

	/**
	 * Obtains the configuration attributes explicitly defined against this bean.
	 * @return the attributes explicitly defined against this bean
	 */
	@Override
	public Collection<ConfigAttribute> getAllConfigAttributes() {
		Set<ConfigAttribute> allAttributes = new HashSet<>();
		this.methodMap.values().forEach(allAttributes::addAll);
		return allAttributes;
	}

	/**
	 * Return if the given method name matches the mapped name. The default implementation
	 * checks for "xxx" and "xxx" matches.
	 * @param methodName the method name of the class
	 * @param mappedName the name in the descriptor
	 * @return if the names match
	 */
	private boolean isMatch(String methodName, String mappedName) {
		return (mappedName.endsWith("*") && methodName.startsWith(mappedName.substring(0, mappedName.length() - 1)))
				|| (mappedName.startsWith("*") && methodName.endsWith(mappedName.substring(1, mappedName.length())));
	}

	@Override
	public void setBeanClassLoader(ClassLoader beanClassLoader) {
		Assert.notNull(beanClassLoader, "Bean class loader required");
		this.beanClassLoader = beanClassLoader;
	}

	/**
	 * @return map size (for unit tests and diagnostics)
	 */
	public int getMethodMapSize() {
		return this.methodMap.size();
	}

	/**
	 * Stores both the Java Method as well as the Class we obtained the Method from. This
	 * is necessary because Method only provides us access to the declaring class. It
	 * doesn't provide a way for us to introspect which Class the Method was registered
	 * against. If a given Class inherits and redeclares a method (i.e. calls super();)
	 * the registered Class and declaring Class are the same. If a given class merely
	 * inherits but does not redeclare a method, the registered Class will be the Class
	 * we're invoking against and the Method will provide details of the declared class.
	 */
	private static class RegisteredMethod {

		private final Method method;

		private final Class<?> registeredJavaType;

		RegisteredMethod(Method method, Class<?> registeredJavaType) {
			Assert.notNull(method, "Method required");
			Assert.notNull(registeredJavaType, "Registered Java Type required");
			this.method = method;
			this.registeredJavaType = registeredJavaType;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			}
			if (obj instanceof RegisteredMethod rhs) {
				return this.method.equals(rhs.method) && this.registeredJavaType.equals(rhs.registeredJavaType);
			}
			return false;
		}

		@Override
		public int hashCode() {
			return this.method.hashCode() * this.registeredJavaType.hashCode();
		}

		@Override
		public String toString() {
			return "RegisteredMethod[" + this.registeredJavaType.getName() + "; " + this.method + "]";
		}

	}

}
