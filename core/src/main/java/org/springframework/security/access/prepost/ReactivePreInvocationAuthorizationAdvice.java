/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.access.prepost;

import org.aopalliance.intercept.MethodInvocation;

import reactor.core.publisher.Mono;

import org.springframework.aop.framework.AopInfrastructureBean;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;

/**
 * Performs reactive argument filtering and authorization logic before a reactive method is invoked.
 * <p>
 *   Reactive equivalent of {@link PreInvocationAuthorizationAdvice}
 * </p>
 *
 * @author Eric Deandrea
 * @since 5.1.2
 * @see PreInvocationAuthorizationAdvice
 */
@FunctionalInterface
public interface ReactivePreInvocationAuthorizationAdvice extends AopInfrastructureBean {
	/**
	 * The "before" advice which should be executed to decide whether the method call is authorized
	 *
	 * @param authentication The information on the principal on whose account the
	 *                       decision should be made
	 * @param mi The method invocation being attempted
	 * @param preInvocationAttribute The attribute built from the {@code @PreFilter} and {@code @PreAuthorize}
	 *                                  annotations
	 * @return A {@link Mono} which emits {@code true} if authorized, {@code false} otherwise
 	 */
	Mono<Boolean> before(Authentication authentication, MethodInvocation mi,
			@Nullable PreInvocationAttribute preInvocationAttribute);
}
