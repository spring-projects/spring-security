/*
 * Copyright 2002-2023 the original author or authors.
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

import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

import org.springframework.security.core.Authentication;

/**
 * A factory class to create an {@link AuthorizationManager} instances.
 *
 * @author Evgeniy Cheban
 * @author Josh Cummings
 * @since 5.8
 */
public final class AuthorizationManagers {

	/**
	 * Creates an {@link AuthorizationManager} that grants access if at least one
	 * {@link AuthorizationManager} granted or abstained, if <code>managers</code> are
	 * empty then denied decision is returned.
	 * @param <T> the type of object that is being authorized
	 * @param managers the {@link AuthorizationManager}s to use
	 * @return the {@link AuthorizationManager} to use
	 */
	@SafeVarargs
	public static <T> AuthorizationManager<T> anyOf(AuthorizationManager<T>... managers) {
		return anyOf(new AuthorizationDecision(false), managers);
	}

	/**
	 * Creates an {@link AuthorizationManager} that grants access if at least one
	 * {@link AuthorizationManager} granted, if <code>managers</code> are empty or
	 * abstained, a default {@link AuthorizationDecision} is returned.
	 * @param <T> the type of object that is being authorized
	 * @param allAbstainDefaultDecision the default decision if all
	 * {@link AuthorizationManager}s abstained
	 * @param managers the {@link AuthorizationManager}s to use
	 * @return the {@link AuthorizationManager} to use
	 * @since 6.3
	 */
	@SafeVarargs
	public static <T> AuthorizationManager<T> anyOf(AuthorizationDecision allAbstainDefaultDecision,
			AuthorizationManager<T>... managers) {
		return (AuthorizationManagerCheckAdapter<T>) (authentication, object) -> {
			List<AuthorizationResult> results = new ArrayList<>();
			for (AuthorizationManager<T> manager : managers) {
				AuthorizationResult result = manager.authorize(authentication, object);
				if (result == null) {
					continue;
				}
				if (result.isGranted()) {
					return result;
				}
				results.add(result);
			}
			if (results.isEmpty()) {
				return allAbstainDefaultDecision;
			}
			return new CompositeAuthorizationDecision(false, results);
		};
	}

	/**
	 * Creates an {@link AuthorizationManager} that grants access if all
	 * {@link AuthorizationManager}s granted or abstained, if <code>managers</code> are
	 * empty then granted decision is returned.
	 * @param <T> the type of object that is being authorized
	 * @param managers the {@link AuthorizationManager}s to use
	 * @return the {@link AuthorizationManager} to use
	 */
	@SafeVarargs
	public static <T> AuthorizationManager<T> allOf(AuthorizationManager<T>... managers) {
		return allOf(new AuthorizationDecision(true), managers);
	}

	/**
	 * Creates an {@link AuthorizationManager} that grants access if all
	 * {@link AuthorizationManager}s granted, if <code>managers</code> are empty or
	 * abstained, a default {@link AuthorizationDecision} is returned.
	 * @param <T> the type of object that is being authorized
	 * @param allAbstainDefaultDecision the default decision if all
	 * {@link AuthorizationManager}s abstained
	 * @param managers the {@link AuthorizationManager}s to use
	 * @return the {@link AuthorizationManager} to use
	 * @since 6.3
	 */
	@SafeVarargs
	public static <T> AuthorizationManager<T> allOf(AuthorizationDecision allAbstainDefaultDecision,
			AuthorizationManager<T>... managers) {
		return (AuthorizationManagerCheckAdapter<T>) (authentication, object) -> {
			List<AuthorizationResult> results = new ArrayList<>();
			for (AuthorizationManager<T> manager : managers) {
				AuthorizationResult result = manager.authorize(authentication, object);
				if (result == null) {
					continue;
				}
				if (!result.isGranted()) {
					return result;
				}
				results.add(result);
			}
			if (results.isEmpty()) {
				return allAbstainDefaultDecision;
			}
			return new CompositeAuthorizationDecision(true, results);
		};
	}

	/**
	 * Creates an {@link AuthorizationManager} that reverses whatever decision the given
	 * {@link AuthorizationManager} granted. If the given {@link AuthorizationManager}
	 * abstains, then the returned manager also abstains.
	 * @param <T> the type of object that is being authorized
	 * @param manager the {@link AuthorizationManager} to reverse
	 * @return the reversing {@link AuthorizationManager}
	 * @since 6.3
	 */
	public static <T> AuthorizationManager<T> not(AuthorizationManager<T> manager) {
		return (authentication, object) -> {
			AuthorizationResult result = manager.authorize(authentication, object);
			if (result == null) {
				return null;
			}
			return new NotAuthorizationDecision(result);
		};
	}

	private AuthorizationManagers() {
	}

	private static final class CompositeAuthorizationDecision extends AuthorizationDecision {

		private final List<AuthorizationResult> results;

		private CompositeAuthorizationDecision(boolean granted, List<AuthorizationResult> results) {
			super(granted);
			this.results = results;
		}

		@Override
		public String toString() {
			return "CompositeAuthorizationDecision [results=" + this.results + ']';
		}

	}

	private static final class NotAuthorizationDecision extends AuthorizationDecision {

		private final AuthorizationResult result;

		private NotAuthorizationDecision(AuthorizationResult result) {
			super(!result.isGranted());
			this.result = result;
		}

		@Override
		public String toString() {
			return "NotAuthorizationDecision [result=" + this.result + ']';
		}

	}

	private interface AuthorizationManagerCheckAdapter<T> extends AuthorizationManager<T> {

		@Override
		default AuthorizationDecision check(Supplier<Authentication> authentication, T object) {
			AuthorizationResult result = authorize(authentication, object);
			if (result == null) {
				return null;
			}
			if (result instanceof AuthorizationDecision decision) {
				return decision;
			}
			throw new IllegalArgumentException(
					"please call #authorize or ensure that the result is of type AuthorizationDecision");
		}

		AuthorizationResult authorize(Supplier<Authentication> authentication, T object);

	}

}
