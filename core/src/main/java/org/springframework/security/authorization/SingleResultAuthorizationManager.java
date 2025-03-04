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
import org.springframework.util.Assert;

/**
 * An {@link AuthorizationManager} which creates permit-all and deny-all
 * {@link AuthorizationManager} instances.
 *
 * @author Max Batischev
 * @since 6.5
 */
public final class SingleResultAuthorizationManager<C> implements AuthorizationManager<C> {

	private static final SingleResultAuthorizationManager<?> DENY_MANAGER = new SingleResultAuthorizationManager<>(
			new AuthorizationDecision(false));

	private static final SingleResultAuthorizationManager<?> PERMIT_MANAGER = new SingleResultAuthorizationManager<>(
			new AuthorizationDecision(true));

	private final AuthorizationResult result;

	public SingleResultAuthorizationManager(AuthorizationResult result) {
		Assert.notNull(result, "result cannot be null");
		this.result = result;
	}

	@Override
	public AuthorizationDecision check(Supplier<Authentication> authentication, C object) {
		if (!(this.result instanceof AuthorizationDecision)) {
			throw new IllegalArgumentException("result should be AuthorizationDecision");
		}
		return (AuthorizationDecision) this.result;
	}

	@Override
	public AuthorizationResult authorize(Supplier<Authentication> authentication, C object) {
		return this.result;
	}

	@SuppressWarnings("unchecked")
	public static <C> SingleResultAuthorizationManager<C> denyAll() {
		return (SingleResultAuthorizationManager<C>) DENY_MANAGER;
	}

	@SuppressWarnings("unchecked")
	public static <C> SingleResultAuthorizationManager<C> permitAll() {
		return (SingleResultAuthorizationManager<C>) PERMIT_MANAGER;
	}

}
