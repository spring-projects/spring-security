/*
 * Copyright 2002-2025 the original author or authors.
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

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Supplier;

import jakarta.annotation.security.DenyAll;
import jakarta.annotation.security.PermitAll;
import jakarta.annotation.security.RolesAllowed;
import org.aopalliance.intercept.MethodInvocation;
import org.jspecify.annotations.Nullable;

import org.springframework.security.authorization.AuthoritiesAuthorizationManager;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.authorization.SingleResultAuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.SecurityAnnotationScanner;
import org.springframework.security.core.annotation.SecurityAnnotationScanners;
import org.springframework.util.Assert;

/**
 * An {@link AuthorizationManager} which can determine if an {@link Authentication} may
 * invoke the {@link MethodInvocation} by evaluating if the {@link Authentication}
 * contains a specified authority from the JSR-250 security annotations.
 *
 * @author Evgeniy Cheban
 * @author Josh Cummings
 * @author DingHao
 * @since 5.6
 */
public final class Jsr250AuthorizationManager implements AuthorizationManager<MethodInvocation> {

	private final Jsr250AuthorizationManagerRegistry registry = new Jsr250AuthorizationManagerRegistry();

	private AuthorizationManager<Collection<String>> authoritiesAuthorizationManager = new AuthoritiesAuthorizationManager();

	private String rolePrefix = "ROLE_";

	/**
	 * Sets an {@link AuthorizationManager} that accepts a collection of authority
	 * strings.
	 * @param authoritiesAuthorizationManager the {@link AuthorizationManager} that
	 * accepts a collection of authority strings to use
	 * @since 6.2
	 */
	public void setAuthoritiesAuthorizationManager(
			AuthorizationManager<Collection<String>> authoritiesAuthorizationManager) {
		Assert.notNull(authoritiesAuthorizationManager, "authoritiesAuthorizationManager cannot be null");
		this.authoritiesAuthorizationManager = authoritiesAuthorizationManager;
	}

	/**
	 * Sets the role prefix. Defaults to "ROLE_".
	 * @param rolePrefix the role prefix to use
	 */
	public void setRolePrefix(String rolePrefix) {
		Assert.notNull(rolePrefix, "rolePrefix cannot be null");
		this.rolePrefix = rolePrefix;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public @Nullable AuthorizationResult authorize(Supplier<Authentication> authentication,
			MethodInvocation methodInvocation) {
		AuthorizationManager<MethodInvocation> delegate = this.registry.getManager(methodInvocation);
		return delegate.authorize(authentication, methodInvocation);
	}

	private final class Jsr250AuthorizationManagerRegistry extends AbstractAuthorizationManagerRegistry {

		private final SecurityAnnotationScanner<?> scanner = SecurityAnnotationScanners
			.requireUnique(List.of(DenyAll.class, PermitAll.class, RolesAllowed.class));

		@Override
		AuthorizationManager<MethodInvocation> resolveManager(Method method, @Nullable Class<?> targetClass) {
			Annotation annotation = findJsr250Annotation(method, targetClass);
			if (annotation instanceof DenyAll) {
				return SingleResultAuthorizationManager.denyAll();
			}
			if (annotation instanceof PermitAll) {
				return SingleResultAuthorizationManager.permitAll();
			}
			if (annotation instanceof RolesAllowed rolesAllowed) {
				return (a, o) -> Jsr250AuthorizationManager.this.authoritiesAuthorizationManager.authorize(a,
						getAllowedRolesWithPrefix(rolesAllowed));
			}
			return NULL_MANAGER;
		}

		private @Nullable Annotation findJsr250Annotation(Method method, @Nullable Class<?> targetClass) {
			Class<?> targetClassToUse = (targetClass != null) ? targetClass : method.getDeclaringClass();
			return this.scanner.scan(method, targetClassToUse);
		}

		private Set<String> getAllowedRolesWithPrefix(RolesAllowed rolesAllowed) {
			Set<String> roles = new HashSet<>();
			for (int i = 0; i < rolesAllowed.value().length; i++) {
				roles.add(Jsr250AuthorizationManager.this.rolePrefix + rolesAllowed.value()[i]);
			}
			return roles;
		}

	}

}
