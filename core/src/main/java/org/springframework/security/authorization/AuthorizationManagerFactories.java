/*
 * Copyright 2002-present the original author or authors.
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

import java.util.function.Consumer;

/**
 * Creates common {@link AuthorizationManagerFactory} instances.
 *
 * @author Rob Winch
 * @since 7.0
 * @see DefaultAuthorizationManagerFactory
 */
public final class AuthorizationManagerFactories {

	private AuthorizationManagerFactories() {
	}

	/**
	 * Creates a {@link AdditionalRequiredFactorsBuilder} that helps build an
	 * {@link AuthorizationManager} to set on
	 * {@link DefaultAuthorizationManagerFactory#setAdditionalAuthorization(AuthorizationManager)}
	 * for multifactor authentication.
	 * <p>
	 * Does not affect {@code anonymous}, {@code permitAll}, or {@code denyAll}.
	 * @param <T> the secured object type
	 * @return a factory configured with the required authorities
	 */
	public static <T> AdditionalRequiredFactorsBuilder<T> multiFactor() {
		return new AdditionalRequiredFactorsBuilder<>();
	}

	/**
	 * A builder that allows creating {@link DefaultAuthorizationManagerFactory} with
	 * additional requirements for {@link RequiredFactor}s.
	 *
	 * @param <T> the type for the {@link DefaultAuthorizationManagerFactory}
	 * @author Rob Winch
	 */
	public static final class AdditionalRequiredFactorsBuilder<T> {

		private final AllRequiredFactorsAuthorizationManager.Builder<T> factors = AllRequiredFactorsAuthorizationManager
			.builder();

		/**
		 * Add additional authorities that will be required.
		 * @param additionalAuthorities the additional authorities.
		 * @return the {@link AdditionalRequiredFactorsBuilder} to further customize.
		 */
		public AdditionalRequiredFactorsBuilder<T> requireFactors(String... additionalAuthorities) {
			requireFactors((factors) -> {
				for (String authority : additionalAuthorities) {
					factors.requireFactor((factor) -> factor.authority(authority));
				}
			});
			return this;
		}

		public AdditionalRequiredFactorsBuilder<T> requireFactors(
				Consumer<AllRequiredFactorsAuthorizationManager.Builder<T>> factors) {
			factors.accept(this.factors);
			return this;
		}

		public AdditionalRequiredFactorsBuilder<T> requireFactor(Consumer<RequiredFactor.Builder> factor) {
			this.factors.requireFactor(factor);
			return this;
		}

		/**
		 * Builds a {@link DefaultAuthorizationManagerFactory} that has the
		 * {@link DefaultAuthorizationManagerFactory#setAdditionalAuthorization(AuthorizationManager)}
		 * set.
		 * @return the {@link DefaultAuthorizationManagerFactory}.
		 */
		public DefaultAuthorizationManagerFactory<T> build() {
			DefaultAuthorizationManagerFactory<T> result = new DefaultAuthorizationManagerFactory<>();
			AllRequiredFactorsAuthorizationManager<T> additionalChecks = this.factors.build();
			result.setAdditionalAuthorization(additionalChecks);
			return result;
		}

		private AdditionalRequiredFactorsBuilder() {
		}

	}

}
