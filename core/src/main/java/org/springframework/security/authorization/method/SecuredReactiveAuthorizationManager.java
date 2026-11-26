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

package org.springframework.security.authorization.method;

import java.util.Collection;

import org.aopalliance.intercept.MethodInvocation;
import reactor.core.publisher.Mono;

import org.springframework.security.access.annotation.Secured;
import org.springframework.security.authorization.AuthoritiesAuthorizationManager;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.core.Authentication;

/**
 * A {@link ReactiveAuthorizationManager} which can determine if an {@link Authentication}
 * may invoke the {@link MethodInvocation} by evaluating if the {@link Authentication}
 * contains a specified authority from Spring Security's {@link Secured} annotation.
 * <p>
 * The annotation is resolved the same way as in {@link SecuredAuthorizationManager}.
 *
 * @author Rohit Behera
 * @since 7.3
 * @see SecuredAuthorizationManager
 */
public final class SecuredReactiveAuthorizationManager implements ReactiveAuthorizationManager<MethodInvocation> {

	private final SecuredAuthorizationManager delegate = new SecuredAuthorizationManager();

	/**
	 * Sets an {@link AuthorizationManager} that accepts a collection of authority
	 * strings. Defaults to {@link AuthoritiesAuthorizationManager}.
	 * @param authoritiesAuthorizationManager the {@link AuthorizationManager} that
	 * accepts a collection of authority strings to use
	 */
	public void setAuthoritiesAuthorizationManager(
			AuthorizationManager<Collection<String>> authoritiesAuthorizationManager) {
		this.delegate.setAuthoritiesAuthorizationManager(authoritiesAuthorizationManager);
	}

	/**
	 * Determines if an {@link Authentication} may invoke the {@link MethodInvocation}
	 * according to the {@link Secured} annotation on the method or its class.
	 * @param authentication the {@link Mono} of the {@link Authentication} to check
	 * @param mi the {@link MethodInvocation} to check
	 * @return a {@link Mono} of the {@link AuthorizationResult} or an empty {@link Mono}
	 * if no {@link Secured} annotation is present
	 */
	@Override
	public Mono<AuthorizationResult> authorize(Mono<Authentication> authentication, MethodInvocation mi) {
		// @formatter:off
		return authentication.singleOptional()
				.mapNotNull((auth) -> this.delegate.authorize(() -> auth.orElse(null), mi));
		// @formatter:on
	}

}
