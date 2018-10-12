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
import org.reactivestreams.Publisher;

import org.springframework.aop.framework.AopInfrastructureBean;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;

/**
 * Performs reactive filtering and authorization logic after a reactive method is invoked.
 * <p>
 *   This is the reactive equivalent of {@link PostInvocationAuthorizationAdvice}
 * </p>
 *
 * @author Eric Deandrea
 * @since 5.1.2
 * @see PostInvocationAuthorizationAdvice
 */
@FunctionalInterface
public interface ReactivePostInvocationAuthorizationAdvice extends AopInfrastructureBean {
	/**
	 * The "after" advice which should be executed to perform any filtering necessary after
	 * method invocation to decide whether the method call was authorized
	 *
	 * @param authentication The information on the principal on whose account the
	 *                       decision should be made
	 * @param mi The method invocation which was executed
	 * @param pia The attribute build from the {@code @PostFilter} and {@code @PostAuthorize}
	 *            annotations
	 * @param returnedObject The object which was returned from the method invocation
	 * @param <T> The type of {@link Publisher}
	 * @return A {@link Publisher} which emits the returnedObject if authorized, or an error
	 * {@link org.springframework.security.access.AccessDeniedException AccessDeniedException} otherwise
	 */
	<T extends Publisher<?>> T after(Authentication authentication, MethodInvocation mi,
			@Nullable PostInvocationAttribute pia, T returnedObject);
}
