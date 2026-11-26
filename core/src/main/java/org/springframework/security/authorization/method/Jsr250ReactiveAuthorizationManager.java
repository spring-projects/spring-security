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

import org.springframework.security.authorization.AuthoritiesAuthorizationManager;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.core.Authentication;

/**
 * A {@link ReactiveAuthorizationManager} which can determine if an {@link Authentication}
 * may invoke the {@link MethodInvocation} by evaluating if the {@link Authentication}
 * contains a specified authority from the JSR-250 security annotations.
 * <p>
 * The annotations are resolved the same way as in {@link Jsr250AuthorizationManager}.
 *
 * @author Rohit Behera
 * @since 7.3
 * @see Jsr250AuthorizationManager
 */
public final class Jsr250ReactiveAuthorizationManager implements ReactiveAuthorizationManager<MethodInvocation> {

	private final Jsr250AuthorizationManager delegate = new Jsr250AuthorizationManager();

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
	 * Sets the role prefix. Defaults to "ROLE_".
	 * @param rolePrefix the role prefix to use
	 */
	public void setRolePrefix(String rolePrefix) {
		this.delegate.setRolePrefix(rolePrefix);
	}

	/**
	 * Determines if an {@link Authentication} may invoke the {@link MethodInvocation}
	 * according to the JSR-250 annotation on the method or its class.
	 * @param authentication the {@link Mono} of the {@link Authentication} to check
	 * @param mi the {@link MethodInvocation} to check
	 * @return a {@link Mono} of the {@link AuthorizationResult} or an empty {@link Mono}
	 * if no JSR-250 annotation is present
	 */
	@Override
	public Mono<AuthorizationResult> authorize(Mono<Authentication> authentication, MethodInvocation mi) {
		// An empty authentication still has to grant @PermitAll, as in the servlet stack
		// @formatter:off
		return authentication.singleOptional()
				.mapNotNull((auth) -> this.delegate.authorize(() -> auth.orElse(null), mi));
		// @formatter:on
	}

}
