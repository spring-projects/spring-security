/*
 * Copyright 2004-present the original author or authors.
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
import java.util.Collection;
import java.util.Collections;

import org.jspecify.annotations.Nullable;

import org.springframework.aop.support.AopUtils;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.authorization.AuthorizationManager;

/**
 * Abstract implementation of {@link MethodSecurityMetadataSource} that supports both
 * Spring AOP and AspectJ and performs attribute resolution from: 1. specific target
 * method; 2. target class; 3. declaring method; 4. declaring class/interface. Use with
 * {@link DelegatingMethodSecurityMetadataSource} for caching support.
 * <p>
 * This class mimics the behaviour of Spring's
 * <tt>AbstractFallbackTransactionAttributeSource</tt> class.
 * <p>
 * Note that this class cannot extract security metadata where that metadata is expressed
 * by way of a target method/class (i.e. #1 and #2 above) AND the target method/class is
 * encapsulated in another proxy object. Spring Security does not walk a proxy chain to
 * locate the concrete/final target object. Consider making Spring Security your final
 * advisor (so it advises the final target, as opposed to another proxy), move the
 * metadata to declared methods or interfaces the proxy implements, or provide your own
 * replacement <tt>MethodSecurityMetadataSource</tt>.
 *
 * @author Ben Alex
 * @author Luke taylor
 * @since 2.0
 * @deprecated Use the {@code use-authorization-manager} attribute for
 * {@code <method-security>} and {@code <intercept-methods>} instead or use
 * annotation-based or {@link AuthorizationManager}-based authorization
 */
@Deprecated
public abstract class AbstractFallbackMethodSecurityMetadataSource extends AbstractMethodSecurityMetadataSource {

	@Override
	public Collection<ConfigAttribute> getAttributes(Method method, @Nullable Class<?> targetClass) {
		// The method may be on an interface, but we need attributes from the target
		// class.
		// If the target class is null, the method will be unchanged.
		Method specificMethod = AopUtils.getMostSpecificMethod(method, targetClass);
		// First try is the method in the target class.
		Collection<ConfigAttribute> attr = findAttributes(specificMethod, targetClass);
		if (attr != null) {
			return attr;
		}
		// Second try is the config attribute on the target class.
		attr = findAttributes(specificMethod.getDeclaringClass());
		if (attr != null) {
			return attr;
		}
		if (specificMethod != method || targetClass == null) {
			// Fallback is to look at the original method.
			attr = findAttributes(method, method.getDeclaringClass());
			if (attr != null) {
				return attr;
			}
			// Last fallback is the class of the original method.
			return findAttributes(method.getDeclaringClass());
		}
		return Collections.emptyList();
	}

	/**
	 * Obtains the security metadata applicable to the specified method invocation.
	 *
	 * <p>
	 * Note that the {@link Method#getDeclaringClass()} may not equal the
	 * <code>targetClass</code>. Both parameters are provided to assist subclasses which
	 * may wish to provide advanced capabilities related to method metadata being
	 * "registered" against a method even if the target class does not declare the method
	 * (i.e. the subclass may only inherit the method).
	 * @param method the method for the current invocation (never <code>null</code>)
	 * @param targetClass the target class for the invocation (may be <code>null</code>)
	 * @return the security metadata (or null if no metadata applies)
	 */
	protected abstract Collection<ConfigAttribute> findAttributes(Method method, @Nullable Class<?> targetClass);

	/**
	 * Obtains the security metadata registered against the specified class.
	 *
	 * <p>
	 * Subclasses should only return metadata expressed at a class level. Subclasses
	 * should NOT aggregate metadata for each method registered against a class, as the
	 * abstract superclass will separate invoke {@link #findAttributes(Method, Class)} for
	 * individual methods as appropriate.
	 * @param clazz the target class for the invocation (never <code>null</code>)
	 * @return the security metadata (or null if no metadata applies)
	 */
	protected abstract Collection<ConfigAttribute> findAttributes(Class<?> clazz);

}
