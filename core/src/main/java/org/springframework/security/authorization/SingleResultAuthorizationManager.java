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

package org.springframework.security.authorization;

import java.util.function.Supplier;

import org.springframework.security.core.Authentication;

/**
 * An {@link AuthorizationManager} which creates permit-all and deny-all
 * {@link AuthorizationManager} instances.
 *
 * @author Max Batischev
 * @since 6.5
 */
public final class SingleResultAuthorizationManager<C> implements AuthorizationManager<C> {

	private static final AuthorizationDecision DENY = new AuthorizationDecision(false);

	private static final AuthorizationDecision PERMIT = new AuthorizationDecision(true);

	/**
	 * Creates permit-all {@link AuthorizationManager} instance.
	 * @param <C>
	 * @return permit-all {@link AuthorizationManager} instance
	 */
	public static <C> AuthorizationManager<C> PERMIT_ALL() {
		return (a, o) -> PERMIT;
	}

	/**
	 * Creates deny-all {@link AuthorizationManager} instance.
	 * @param <C>
	 * @return deny-all {@link AuthorizationManager} instance
	 */
	public static <C> AuthorizationManager<C> DENY_ALL() {
		return (a, o) -> DENY;
	}

	private SingleResultAuthorizationManager() {
	}

	@Override
	public AuthorizationDecision check(Supplier<Authentication> authentication, C object) {
		throw new UnsupportedOperationException("Not supported");
	}

}
