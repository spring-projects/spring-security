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
import java.util.function.Supplier;

import org.aopalliance.intercept.MethodInvocation;

import org.springframework.aop.support.AopUtils;
import org.springframework.lang.NonNull;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;

/**
 * An {@link AuthorizationManager} which can determine if an {@link Authentication} may
 * invoke the {@link MethodInvocation} by evaluating if the {@link Authentication}
 * contains a specified authority from the Spring Security's {@link Secured} annotation.
 *
 * @author Evgeniy Cheban
 * @since 5.6
 */
public final class SecuredAuthorizationManager implements AuthorizationManager<MethodInvocation> {

	private final SecuredAuthorizationManagerRegistry registry = new SecuredAuthorizationManagerRegistry();

	/**
	 * Determine if an {@link Authentication} has access to a method by evaluating the
	 * {@link Secured} annotation that {@link MethodInvocation} specifies.
	 * @param authentication the {@link Supplier} of the {@link Authentication} to check
	 * @param mi the {@link MethodInvocation} to check
	 * @return an {@link AuthorizationDecision} or null if the {@link Secured} annotation
	 * is not present
	 */
	@Override
	public AuthorizationDecision check(Supplier<Authentication> authentication, MethodInvocation mi) {
		AuthorizationManager<MethodInvocation> delegate = this.registry.getManager(mi);
		return delegate.check(authentication, mi);
	}

	private static final class SecuredAuthorizationManagerRegistry extends AbstractAuthorizationManagerRegistry {

		@NonNull
		@Override
		AuthorizationManager<MethodInvocation> resolveManager(Method method, Class<?> targetClass) {
			Method specificMethod = AopUtils.getMostSpecificMethod(method, targetClass);
			Secured secured = findSecuredAnnotation(specificMethod);
			return (secured != null) ? AuthorityAuthorizationManager.hasAnyAuthority(secured.value()) : NULL_MANAGER;
		}

		private Secured findSecuredAnnotation(Method method) {
			Secured secured = AuthorizationAnnotationUtils.findUniqueAnnotation(method, Secured.class);
			return (secured != null) ? secured
					: AuthorizationAnnotationUtils.findUniqueAnnotation(method.getDeclaringClass(), Secured.class);
		}

	}

}
