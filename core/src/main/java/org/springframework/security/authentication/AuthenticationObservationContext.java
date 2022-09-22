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

package org.springframework.security.authentication;

import io.micrometer.observation.Observation;

import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

/**
 * An {@link Observation.Context} used during authentications
 *
 * @author Josh Cummings
 * @since 6.0
 */
public class AuthenticationObservationContext extends Observation.Context {

	private Authentication authenticationRequest;

	private Class<?> authenticationManager;

	private Authentication authenticationResult;

	/**
	 * Get the {@link Authentication} request that was observed
	 * @return the observed {@link Authentication} request
	 */
	public Authentication getAuthenticationRequest() {
		return this.authenticationRequest;
	}

	/**
	 * Set the {@link Authentication} request that was observed
	 * @param authenticationRequest the observed {@link Authentication} request
	 */
	public void setAuthenticationRequest(Authentication authenticationRequest) {
		Assert.notNull(authenticationRequest, "authenticationRequest cannot be null");
		this.authenticationRequest = authenticationRequest;
	}

	/**
	 * Get the {@link Authentication} result that was observed
	 *
	 * <p>
	 * Note that if authentication failed, no {@link Authentication} result can be
	 * observed. In that case, this returns {@code null}.
	 * @return any observed {@link Authentication} result, {@code null} otherwise
	 */
	public Authentication getAuthenticationResult() {
		return this.authenticationResult;
	}

	/**
	 * Set the {@link Authentication} result that was observed
	 * @param authenticationResult the observed {@link Authentication} result
	 */
	public void setAuthenticationResult(Authentication authenticationResult) {
		this.authenticationResult = authenticationResult;
	}

	/**
	 * Get the {@link AuthenticationManager} class that processed the authentication
	 * @return the observed {@link AuthenticationManager} class
	 */
	public Class<?> getAuthenticationManagerClass() {
		return this.authenticationManager;
	}

	/**
	 * Set the {@link AuthenticationManager} class that processed the authentication
	 * @param authenticationManagerClass the observed {@link AuthenticationManager} class
	 */
	public void setAuthenticationManagerClass(Class<?> authenticationManagerClass) {
		Assert.notNull(authenticationManagerClass, "authenticationManagerClass class cannot be null");
		this.authenticationManager = authenticationManagerClass;
	}

}
