/*
 * Copyright 2002-2022 the original author or authors.
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

import io.micrometer.observation.Observation;

import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

/**
 * An {@link Observation.Context} used during authorizations
 *
 * @author Josh Cummings
 * @since 6.0
 */
public class AuthorizationObservationContext<T> extends Observation.Context {

	private Authentication authentication;

	private final T object;

	private AuthorizationDecision decision;

	public AuthorizationObservationContext(T object) {
		Assert.notNull(object, "object cannot be null");
		this.object = object;
	}

	/**
	 * Get the observed {@link Authentication} for this authorization
	 *
	 * <p>
	 * Note that if the authorization did not require inspecting the
	 * {@link Authentication}, this will return {@code null}.
	 * @return any observed {@link Authentication}, {@code null} otherwise
	 */
	public Authentication getAuthentication() {
		return this.authentication;
	}

	/**
	 * Set the observed {@link Authentication} for this authorization
	 * @param authentication the observed {@link Authentication}
	 */
	public void setAuthentication(Authentication authentication) {
		this.authentication = authentication;
	}

	/**
	 * Get the object for which access was requested
	 * @return the requested object
	 */
	public T getObject() {
		return this.object;
	}

	/**
	 * Get the observed {@link AuthorizationDecision}
	 * @return the observed {@link AuthorizationDecision}
	 */
	public AuthorizationDecision getDecision() {
		return this.decision;
	}

	/**
	 * Set the observed {@link AuthorizationDecision}
	 * @param decision the observed {@link AuthorizationDecision}
	 */
	public void setDecision(AuthorizationDecision decision) {
		this.decision = decision;
	}

}
