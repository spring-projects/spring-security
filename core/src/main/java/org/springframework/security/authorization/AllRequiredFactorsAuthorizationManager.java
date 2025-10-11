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

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import org.jspecify.annotations.Nullable;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.util.Assert;

/**
 * An {@link AuthorizationManager} that determines if the current user is authorized by
 * evaluating if the {@link Authentication} contains a {@link FactorGrantedAuthority} that
 * is not expired for each {@link RequiredFactor}.
 *
 * @author Rob Winch
 * @since 7.0
 * @see AuthorityAuthorizationManager
 */
public final class AllRequiredFactorsAuthorizationManager<T> implements AuthorizationManager<T> {

	private Clock clock = Clock.systemUTC();

	private final List<RequiredFactor> requiredFactors;

	/**
	 * Creates a new instance.
	 * @param requiredFactors the authorities that are required.
	 */
	private AllRequiredFactorsAuthorizationManager(List<RequiredFactor> requiredFactors) {
		Assert.notEmpty(requiredFactors, "requiredFactors cannot be empty");
		Assert.noNullElements(requiredFactors, "requiredFactors must not contain null elements");
		this.requiredFactors = Collections.unmodifiableList(requiredFactors);
	}

	/**
	 * Sets the {@link Clock} to use.
	 * @param clock the {@link Clock} to use. Cannot be null.
	 */
	public void setClock(Clock clock) {
		Assert.notNull(clock, "clock cannot be null");
		this.clock = clock;
	}

	/**
	 * For each {@link RequiredFactor} finds the first
	 * {@link FactorGrantedAuthority#getAuthority()} that matches the
	 * {@link RequiredFactor#getAuthority()}. The
	 * {@link FactorGrantedAuthority#getIssuedAt()} must be more recent than
	 * {@link RequiredFactor#getValidDuration()} (if non-null).
	 * @param authentication the {@link Supplier} of the {@link Authentication} to check
	 * @param object the object to check authorization on (not used).
	 * @return an {@link FactorAuthorizationDecision}
	 */
	@Override
	public FactorAuthorizationDecision authorize(Supplier<? extends @Nullable Authentication> authentication,
			T object) {
		List<GrantedAuthority> currentFactorAuthorities = getFactorGrantedAuthorities(authentication.get());
		List<RequiredFactorError> factorErrors = this.requiredFactors.stream()
			.map((factor) -> requiredFactorError(factor, currentFactorAuthorities))
			.filter(Objects::nonNull)
			.toList();
		return new FactorAuthorizationDecision(factorErrors);
	}

	/**
	 * Given the {@link RequiredFactor} and the current {@link FactorGrantedAuthority}
	 * instances, returns {@link RequiredFactor} or null if granted.
	 * @param requiredFactor the {@link RequiredFactor} to check.
	 * @param currentFactors the current user's {@link FactorGrantedAuthority}.
	 * @return the {@link RequiredFactor} or null if granted.
	 */
	private @Nullable RequiredFactorError requiredFactorError(RequiredFactor requiredFactor,
			List<GrantedAuthority> currentFactors) {
		Optional<GrantedAuthority> matchingAuthority = currentFactors.stream()
			.filter((authority) -> Objects.equals(authority.getAuthority(), requiredFactor.getAuthority()))
			.findFirst();
		if (!matchingAuthority.isPresent()) {
			return RequiredFactorError.createMissing(requiredFactor);
		}
		return matchingAuthority.map((authority) -> {
			if (requiredFactor.getValidDuration() == null) {
				// granted (only requires authority to match)
				return null;
			}
			else if (authority instanceof FactorGrantedAuthority factorAuthority) {
				Instant now = this.clock.instant();
				Instant expiresAt = factorAuthority.getIssuedAt().plus(requiredFactor.getValidDuration());
				if (now.isBefore(expiresAt)) {
					// granted
					return null;
				}
			}

			// denied (expired or no issuedAt to compare)
			return RequiredFactorError.createExpired(requiredFactor);
		}).orElse(null);
	}

	/**
	 * Extracts all of the {@link FactorGrantedAuthority} instances from
	 * {@link Authentication#getAuthorities()}. If {@link Authentication} is null, or
	 * {@link Authentication#isAuthenticated()} is false, then an empty {@link List} is
	 * returned.
	 * @param authentication the {@link Authentication} (possibly null).
	 * @return all of the {@link FactorGrantedAuthority} instances from
	 * {@link Authentication#getAuthorities()}.
	 */
	private List<GrantedAuthority> getFactorGrantedAuthorities(@Nullable Authentication authentication) {
		if (authentication == null || !authentication.isAuthenticated()) {
			return Collections.emptyList();
		}
		// @formatter:off
		return authentication.getAuthorities().stream()
			.collect(Collectors.toList());
		// @formatter:on
	}

	/**
	 * Creates a new {@link Builder}
	 * @return
	 */
	public static <T> Builder<T> builder() {
		return new Builder<>();
	}

	/**
	 * A builder for {@link AllRequiredFactorsAuthorizationManager}.
	 *
	 * @author Rob Winch
	 * @since 7.0
	 */
	public static final class Builder<T> {

		private List<RequiredFactor> requiredFactors = new ArrayList<>();

		/**
		 * Allows the user to consume the {@link RequiredFactor.Builder} that is passed in
		 * and then adds the result to the {@link #requireFactor(RequiredFactor)}.
		 * @param requiredFactor the {@link Consumer} to invoke.
		 * @return the builder.
		 */
		public Builder<T> requireFactor(Consumer<RequiredFactor.Builder> requiredFactor) {
			Assert.notNull(requiredFactor, "requiredFactor cannot be null");
			RequiredFactor.Builder builder = RequiredFactor.builder();
			requiredFactor.accept(builder);
			return requireFactor(builder.build());
		}

		/**
		 * The {@link RequiredFactor} to add.
		 * @param requiredFactor the requiredFactor to add. Cannot be null.
		 * @return the builder.
		 */
		public Builder<T> requireFactor(RequiredFactor requiredFactor) {
			Assert.notNull(requiredFactor, "requiredFactor cannot be null");
			this.requiredFactors.add(requiredFactor);
			return this;
		}

		/**
		 * Builds the {@link AllRequiredFactorsAuthorizationManager}.
		 * @return the {@link AllRequiredFactorsAuthorizationManager}
		 */
		public AllRequiredFactorsAuthorizationManager<T> build() {
			Assert.state(!this.requiredFactors.isEmpty(), "requiredFactors cannot be empty");
			return new AllRequiredFactorsAuthorizationManager<T>(this.requiredFactors);
		}

	}

}
