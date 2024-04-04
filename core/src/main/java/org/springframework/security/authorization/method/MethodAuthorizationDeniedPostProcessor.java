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

import org.springframework.lang.Nullable;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.authorization.AuthorizationResult;

/**
 * An interface to define a strategy to handle denied method invocation results
 *
 * @author Marcus da Coregio
 * @since 6.3
 * @see org.springframework.security.access.prepost.PostAuthorize
 */
public interface MethodAuthorizationDeniedPostProcessor {

	/**
	 * Post-process the denied result produced by a method invocation, implementations
	 * might either throw an
	 * {@link org.springframework.security.access.AccessDeniedException} or return a
	 * replacement result instead of the denied result, e.g. a masked value.
	 * @param methodInvocationResult the object containing the method invocation and the
	 * result produced
	 * @param authorizationResult the {@link AuthorizationResult} containing the
	 * authorization denied details
	 * @return a replacement result for the denied result, or null, or a
	 * {@link reactor.core.publisher.Mono} for reactive applications
	 */
	@Nullable
	Object postProcessResult(MethodInvocationResult methodInvocationResult, AuthorizationResult authorizationResult);

	/**
	 * Post-process the denied result produced by a method invocation, implementations
	 * might either throw an
	 * {@link org.springframework.security.access.AccessDeniedException} or return a
	 * replacement result instead of the denied result, e.g. a masked value.
	 * @param methodInvocationResult the object containing the method invocation and the
	 * result produced
	 * @param authorizationDenied the {@link AuthorizationDeniedException} containing the
	 * authorization denied details
	 * @return a replacement result for the denied result, or null, or a
	 * {@link reactor.core.publisher.Mono} for reactive applications
	 */
	default Object postProcessResult(MethodInvocationResult methodInvocationResult,
			AuthorizationDeniedException authorizationDenied) {
		return postProcessResult(methodInvocationResult, authorizationDenied.getAuthorizationResult());
	}

}
