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

import java.lang.annotation.Annotation;
import java.lang.reflect.AnnotatedElement;
import java.lang.reflect.Method;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Supplier;

import javax.annotation.security.DenyAll;
import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;

import org.aopalliance.intercept.MethodInvocation;

import org.springframework.aop.support.AopUtils;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.lang.NonNull;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

/**
 * An {@link AuthorizationManager} which can determine if an {@link Authentication} has
 * access to the {@link MethodInvocation} by evaluating if the {@link Authentication}
 * contains a specified authority from the JSR-250 security annotations.
 *
 * @author Evgeniy Cheban
 * @since 5.5
 */
public final class Jsr250AuthorizationManager implements AuthorizationManager<MethodAuthorizationContext> {

	private static final Set<Class<? extends Annotation>> JSR250_ANNOTATIONS = new HashSet<>();

	static {
		JSR250_ANNOTATIONS.add(DenyAll.class);
		JSR250_ANNOTATIONS.add(PermitAll.class);
		JSR250_ANNOTATIONS.add(RolesAllowed.class);
	}

	private final Jsr250AuthorizationManagerRegistry registry = new Jsr250AuthorizationManagerRegistry();

	private String rolePrefix = "ROLE_";

	/**
	 * Sets the role prefix. Defaults to "ROLE_".
	 * @param rolePrefix the role prefix to use
	 */
	public void setRolePrefix(String rolePrefix) {
		Assert.notNull(rolePrefix, "rolePrefix cannot be null");
		this.rolePrefix = rolePrefix;
	}

	/**
	 * Determines if an {@link Authentication} has access to the {@link MethodInvocation}
	 * by evaluating if the {@link Authentication} contains a specified authority from the
	 * JSR-250 security annotations.
	 * @param authentication the {@link Supplier} of the {@link Authentication} to check
	 * @param methodAuthorizationContext the {@link MethodAuthorizationContext} to check
	 * @return an {@link AuthorizationDecision} or null if the JSR-250 security
	 * annotations is not present
	 */
	@Override
	public AuthorizationDecision check(Supplier<Authentication> authentication,
			MethodAuthorizationContext methodAuthorizationContext) {
		AuthorizationManager<MethodAuthorizationContext> delegate = this.registry
				.getManager(methodAuthorizationContext);
		return delegate.check(authentication, methodAuthorizationContext);
	}

	private final class Jsr250AuthorizationManagerRegistry extends AbstractAuthorizationManagerRegistry {

		@NonNull
		@Override
		AuthorizationManager<MethodAuthorizationContext> resolveManager(Method method, Class<?> targetClass) {
			for (Annotation annotation : findJsr250Annotations(method, targetClass)) {
				if (annotation instanceof DenyAll) {
					return (a, o) -> new AuthorizationDecision(false);
				}
				if (annotation instanceof PermitAll) {
					return (a, o) -> new AuthorizationDecision(true);
				}
				if (annotation instanceof RolesAllowed) {
					RolesAllowed rolesAllowed = (RolesAllowed) annotation;
					return AuthorityAuthorizationManager.hasAnyRole(Jsr250AuthorizationManager.this.rolePrefix,
							rolesAllowed.value());
				}
			}
			return NULL_MANAGER;
		}

		private Set<Annotation> findJsr250Annotations(Method method, Class<?> targetClass) {
			Method specificMethod = AopUtils.getMostSpecificMethod(method, targetClass);
			Set<Annotation> annotations = findAnnotations(specificMethod);
			return (annotations.isEmpty()) ? findAnnotations(specificMethod.getDeclaringClass()) : annotations;
		}

		private Set<Annotation> findAnnotations(AnnotatedElement annotatedElement) {
			return AnnotatedElementUtils.findAllMergedAnnotations(annotatedElement, JSR250_ANNOTATIONS);
		}

	}

}
