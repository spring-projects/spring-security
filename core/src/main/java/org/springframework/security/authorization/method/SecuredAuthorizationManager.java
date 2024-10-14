/*
 * Copyright 2002-2024 the original author or authors.
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
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

import org.aopalliance.intercept.MethodInvocation;

import org.springframework.core.MethodClassKey;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.authorization.AuthoritiesAuthorizationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.SecurityAnnotationScanner;
import org.springframework.security.core.annotation.SecurityAnnotationScanners;
import org.springframework.util.Assert;

/**
 * An {@link AuthorizationManager} which can determine if an {@link Authentication} may
 * invoke the {@link MethodInvocation} by evaluating if the {@link Authentication}
 * contains a specified authority from the Spring Security's {@link Secured} annotation.
 *
 * @author Evgeniy Cheban
 * @author DingHao
 * @since 5.6
 */
public final class SecuredAuthorizationManager implements AuthorizationManager<MethodInvocation> {

	private AuthorizationManager<Collection<String>> authoritiesAuthorizationManager = new AuthoritiesAuthorizationManager();

	private final Map<MethodClassKey, Set<String>> cachedAuthorities = new ConcurrentHashMap<>();

	private final SecurityAnnotationScanner<Secured> scanner = SecurityAnnotationScanners.requireUnique(Secured.class);

	/**
	 * Sets an {@link AuthorizationManager} that accepts a collection of authority
	 * strings.
	 * @param authoritiesAuthorizationManager the {@link AuthorizationManager} that
	 * accepts a collection of authority strings to use
	 * @since 6.1
	 */
	public void setAuthoritiesAuthorizationManager(
			AuthorizationManager<Collection<String>> authoritiesAuthorizationManager) {
		Assert.notNull(authoritiesAuthorizationManager, "authoritiesAuthorizationManager cannot be null");
		this.authoritiesAuthorizationManager = authoritiesAuthorizationManager;
	}

	/**
	 * Determine if an {@link Authentication} has access to a method by evaluating the
	 * {@link Secured} annotation that {@link MethodInvocation} specifies.
	 * @param authentication the {@link Supplier} of the {@link Authentication} to check
	 * @param mi the {@link MethodInvocation} to check
	 * @return an {@link AuthorizationDecision} or null if the {@link Secured} annotation
	 * is not present
	 * @deprecated please use {@link #authorize(Supplier, Object)} instead
	 */
	@Deprecated
	@Override
	public AuthorizationDecision check(Supplier<Authentication> authentication, MethodInvocation mi) {
		Set<String> authorities = getAuthorities(mi);
		return authorities.isEmpty() ? null : this.authoritiesAuthorizationManager.check(authentication, authorities);
	}

	private Set<String> getAuthorities(MethodInvocation methodInvocation) {
		Method method = methodInvocation.getMethod();
		Object target = methodInvocation.getThis();
		Class<?> targetClass = (target != null) ? target.getClass() : null;
		MethodClassKey cacheKey = new MethodClassKey(method, targetClass);
		return this.cachedAuthorities.computeIfAbsent(cacheKey, (k) -> resolveAuthorities(method, targetClass));
	}

	private Set<String> resolveAuthorities(Method method, Class<?> targetClass) {
		Secured secured = findSecuredAnnotation(method, targetClass);
		return (secured != null) ? Set.of(secured.value()) : Collections.emptySet();
	}

	private Secured findSecuredAnnotation(Method method, Class<?> targetClass) {
		Class<?> targetClassToUse = (targetClass != null) ? targetClass : method.getDeclaringClass();
		return this.scanner.scan(method, targetClassToUse);
	}

}
