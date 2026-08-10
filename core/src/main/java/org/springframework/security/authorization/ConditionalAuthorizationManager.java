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

package org.springframework.security.authorization;

import java.util.function.Predicate;
import java.util.function.Supplier;

import org.jspecify.annotations.Nullable;

import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

/**
 * An {@link AuthorizationManager} that delegates to one of two
 * {@link AuthorizationManager} instances based on a condition evaluated against the
 * current {@link Authentication}.
 * <p>
 * When {@link #authorize(Supplier, Object)} is invoked, the condition is evaluated. If
 * the {@link Authentication} is non-null and the condition returns {@code true}, the
 * {@code whenTrue} manager is used; otherwise the {@code whenFalse} manager is used.
 * <p>
 * This is useful for scenarios such as requiring multi-factor authentication only when
 * the user has registered a second factor, or applying different rules based on
 * authentication state.
 *
 * @param <T> the type of object that the authorization check is being performed on
 * @author Rob Winch
 * @since 7.1
 */
public final class ConditionalAuthorizationManager<T> implements AuthorizationManager<T> {

	private final Predicate<Authentication> condition;

	private final AuthorizationManager<T> whenTrue;

	private final AuthorizationManager<T> whenFalse;

	/**
	 * Creates a {@link ConditionalAuthorizationManager} that delegates to
	 * {@code whenTrue} when the condition holds for the current {@link Authentication},
	 * and to {@code whenFalse} otherwise.
	 * @param condition the condition to evaluate against the {@link Authentication} (must
	 * not be null)
	 * @param whenTrue the manager to use when the condition is true (must not be null)
	 * @param whenFalse the manager to use when the condition is false (must not be null)
	 */
	private ConditionalAuthorizationManager(Predicate<Authentication> condition, AuthorizationManager<T> whenTrue,
			AuthorizationManager<T> whenFalse) {
		Assert.notNull(condition, "condition cannot be null");
		Assert.notNull(whenTrue, "whenTrue cannot be null");
		Assert.notNull(whenFalse, "whenFalse cannot be null");
		this.condition = condition;
		this.whenTrue = whenTrue;
		this.whenFalse = whenFalse;
	}

	/**
	 * Creates a builder for a {@link ConditionalAuthorizationManager} with the given
	 * condition.
	 * @param <T> the type of object that the authorization check is being performed on
	 * @param condition the condition to evaluate against the {@link Authentication} (must
	 * not be null)
	 * @return the builder
	 */
	public static <T> Builder<T> when(Predicate<Authentication> condition) {
		Assert.notNull(condition, "condition cannot be null");
		return new Builder<>(condition);
	}

	@Override
	public @Nullable AuthorizationResult authorize(Supplier<? extends @Nullable Authentication> authentication,
			T object) {
		Authentication auth = authentication.get();
		if (auth != null && this.condition.test(auth)) {
			return this.whenTrue.authorize(authentication, object);
		}
		return this.whenFalse.authorize(authentication, object);
	}

	/**
	 * A builder for {@link ConditionalAuthorizationManager}.
	 *
	 * @param <T> the type of object that the authorization check is being performed on
	 * @author Rob Winch
	 * @since 7.1
	 */
	public static final class Builder<T> {

		private final Predicate<Authentication> condition;

		private @Nullable AuthorizationManager<T> whenTrue;

		private @Nullable AuthorizationManager<T> whenFalse;

		private Builder(Predicate<Authentication> condition) {
			this.condition = condition;
		}

		/**
		 * Sets the {@link AuthorizationManager} to use when the condition is true.
		 * @param whenTrue the manager to use when the condition is true (must not be
		 * null)
		 * @return the builder
		 */
		public Builder<T> whenTrue(AuthorizationManager<T> whenTrue) {
			Assert.notNull(whenTrue, "whenTrue cannot be null");
			this.whenTrue = whenTrue;
			return this;
		}

		/**
		 * Sets the {@link AuthorizationManager} to use when the condition is false.
		 * Defaults to {@link SingleResultAuthorizationManager#permitAll()} if not set.
		 * @param whenFalse the manager to use when the condition is false (must not be
		 * null)
		 * @return the builder
		 */
		public Builder<T> whenFalse(AuthorizationManager<T> whenFalse) {
			Assert.notNull(whenFalse, "whenFalse cannot be null");
			this.whenFalse = whenFalse;
			return this;
		}

		/**
		 * Builds the {@link ConditionalAuthorizationManager}.
		 * @return the {@link ConditionalAuthorizationManager}
		 */
		@SuppressWarnings("unchecked")
		public ConditionalAuthorizationManager<T> build() {
			Assert.state(this.whenTrue != null, "whenTrue is required");
			AuthorizationManager<T> whenFalse = this.whenFalse;
			if (whenFalse == null) {
				whenFalse = (AuthorizationManager<T>) SingleResultAuthorizationManager.permitAll();
			}
			return new ConditionalAuthorizationManager<>(this.condition, this.whenTrue, whenFalse);
		}

	}

}
