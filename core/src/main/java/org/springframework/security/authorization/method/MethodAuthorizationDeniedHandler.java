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

import org.aopalliance.intercept.MethodInvocation;

import org.springframework.lang.Nullable;
import org.springframework.security.authorization.AuthorizationResult;

/**
 * An interface used to define a strategy to handle denied method invocations
 *
 * @author Marcus da Coregio
 * @since 6.3
 * @see org.springframework.security.access.prepost.PreAuthorize
 * @see org.springframework.security.access.prepost.PostAuthorize
 */
public interface MethodAuthorizationDeniedHandler {

	/**
	 * Handle denied method invocations, implementations might either throw an
	 * {@link org.springframework.security.authorization.AuthorizationDeniedException} or
	 * a replacement result instead of invoking the method, e.g. a masked value.
	 * @param methodInvocation the {@link MethodInvocation} related to the authorization
	 * denied
	 * @param authorizationResult the authorization denied result
	 * @return a replacement result for the denied method invocation, or null, or a
	 * {@link reactor.core.publisher.Mono} for reactive applications
	 */
	@Nullable
	Object handleDeniedInvocation(MethodInvocation methodInvocation, AuthorizationResult authorizationResult);

	/**
	 * Handle denied method invocations, implementations might either throw an
	 * {@link org.springframework.security.authorization.AuthorizationDeniedException} or
	 * a replacement result instead of invoking the method, e.g. a masked value. By
	 * default, this method invokes
	 * {@link #handleDeniedInvocation(MethodInvocation, AuthorizationResult)}.
	 * @param methodInvocationResult the object containing the {@link MethodInvocation}
	 * and the result produced
	 * @param authorizationResult the authorization denied result
	 * @return a replacement result for the denied method invocation, or null, or a
	 * {@link reactor.core.publisher.Mono} for reactive applications
	 */
	@Nullable
	default Object handleDeniedInvocationResult(MethodInvocationResult methodInvocationResult,
			AuthorizationResult authorizationResult) {
		return handleDeniedInvocation(methodInvocationResult.getMethodInvocation(), authorizationResult);
	}

}
