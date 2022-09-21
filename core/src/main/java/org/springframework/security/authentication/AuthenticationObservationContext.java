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

import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;

public class AuthenticationObservationContext extends Observation.Context {

	private Authentication authenticationRequest;

	private Class<?> authenticationManager;

	private Authentication authenticationResult;

	public static AuthenticationObservationContext fromEvent(AuthenticationSuccessEvent event) {
		AuthenticationObservationContext context = new AuthenticationObservationContext();
		context.setName("spring.security." + event.getEventType());
		context.setAuthenticationResult(event.getAuthentication());
		return context;
	}

	public static AuthenticationObservationContext fromEvent(AbstractAuthenticationFailureEvent event) {
		AuthenticationObservationContext context = new AuthenticationObservationContext();
		context.setName("spring.security." + event.getEventType());
		context.setAuthenticationRequest(event.getAuthentication());
		context.setError(event.getException());
		return context;
	}

	public Authentication getAuthenticationRequest() {
		return this.authenticationRequest;
	}

	public void setAuthenticationRequest(Authentication authenticationRequest) {
		this.authenticationRequest = authenticationRequest;
	}

	public Authentication getAuthenticationResult() {
		return this.authenticationResult;
	}

	public void setAuthenticationResult(Authentication authenticationResult) {
		this.authenticationResult = authenticationResult;
	}

	public Class<?> getAuthenticationManager() {
		return this.authenticationManager;
	}

	public void setAuthenticationManager(Class<?> authenticationManager) {
		this.authenticationManager = authenticationManager;
	}

}
