/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.authorization.method;

import java.lang.reflect.Method;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.aopalliance.intercept.MethodInvocation;

import org.springframework.core.MethodClassKey;
import org.springframework.lang.NonNull;
import org.springframework.security.authorization.AuthorizationManager;

/**
 * An abstract registry which provides an {@link AuthorizationManager} for the
 * {@link MethodInvocation}.
 *
 * @author Evgeniy Cheban
 * @since 5.5
 */
abstract class AbstractAuthorizationManagerRegistry {

	static final AuthorizationManager<MethodAuthorizationContext> NULL_MANAGER = (a, o) -> null;

	private final Map<MethodClassKey, AuthorizationManager<MethodAuthorizationContext>> cachedManagers = new ConcurrentHashMap<>();

	/**
	 * Returns an {@link AuthorizationManager} for the {@link MethodAuthorizationContext}.
	 * @param methodAuthorizationContext the {@link MethodAuthorizationContext} to use
	 * @return an {@link AuthorizationManager} to use
	 */
	final AuthorizationManager<MethodAuthorizationContext> getManager(
			MethodAuthorizationContext methodAuthorizationContext) {
		MethodInvocation methodInvocation = methodAuthorizationContext.getMethodInvocation();
		Method method = methodInvocation.getMethod();
		Class<?> targetClass = methodAuthorizationContext.getTargetClass();
		MethodClassKey cacheKey = new MethodClassKey(method, targetClass);
		return this.cachedManagers.computeIfAbsent(cacheKey, (k) -> resolveManager(method, targetClass));
	}

	/**
	 * Subclasses should implement this method to provide the non-null
	 * {@link AuthorizationManager} for the method and the target class.
	 * @param method the method
	 * @param targetClass the target class
	 * @return the non-null {@link AuthorizationManager}
	 */
	@NonNull
	abstract AuthorizationManager<MethodAuthorizationContext> resolveManager(Method method, Class<?> targetClass);

}
