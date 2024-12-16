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

package org.springframework.security.config.observation;

import io.micrometer.observation.ObservationPredicate;

/**
 * An {@link ObservationPredicate} that can be used to change which Spring Security
 * observations are made with Micrometer.
 *
 * <p>
 * By default, web requests are not observed and authentications and authorizations are
 * observed.
 *
 * @author Josh Cummings
 * @since 6.4
 */
public final class SecurityObservationSettings {

	private final boolean observeRequests;

	private final boolean observeAuthentications;

	private final boolean observeAuthorizations;

	private SecurityObservationSettings(boolean observeRequests, boolean observeAuthentications,
			boolean observeAuthorizations) {
		this.observeRequests = observeRequests;
		this.observeAuthentications = observeAuthentications;
		this.observeAuthorizations = observeAuthorizations;
	}

	/**
	 * Make no Spring Security observations
	 * @return a {@link SecurityObservationSettings} with all exclusions turned on
	 */
	public static SecurityObservationSettings noObservations() {
		return new SecurityObservationSettings(false, false, false);
	}

	/**
	 * Begin the configuration of a {@link SecurityObservationSettings}
	 * @return a {@link Builder} where filter chain observations are off and authn/authz
	 * observations are on
	 */
	public static Builder withDefaults() {
		return new Builder(false, true, true);
	}

	public boolean shouldObserveRequests() {
		return this.observeRequests;
	}

	public boolean shouldObserveAuthentications() {
		return this.observeAuthentications;
	}

	public boolean shouldObserveAuthorizations() {
		return this.observeAuthorizations;
	}

	/**
	 * A builder for configuring a {@link SecurityObservationSettings}
	 */
	public static final class Builder {

		private boolean observeRequests;

		private boolean observeAuthentications;

		private boolean observeAuthorizations;

		Builder(boolean observeRequests, boolean observeAuthentications, boolean observeAuthorizations) {
			this.observeRequests = observeRequests;
			this.observeAuthentications = observeAuthentications;
			this.observeAuthorizations = observeAuthorizations;
		}

		public Builder shouldObserveRequests(boolean excludeFilters) {
			this.observeRequests = excludeFilters;
			return this;
		}

		public Builder shouldObserveAuthentications(boolean excludeAuthentications) {
			this.observeAuthentications = excludeAuthentications;
			return this;
		}

		public Builder shouldObserveAuthorizations(boolean excludeAuthorizations) {
			this.observeAuthorizations = excludeAuthorizations;
			return this;
		}

		public SecurityObservationSettings build() {
			return new SecurityObservationSettings(this.observeRequests, this.observeAuthentications,
					this.observeAuthorizations);
		}

	}

}
