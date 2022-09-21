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

import java.util.function.Supplier;

import io.micrometer.observation.Observation;

import org.springframework.security.authorization.event.AuthorizationDeniedEvent;
import org.springframework.security.authorization.event.AuthorizationGrantedEvent;
import org.springframework.security.core.Authentication;

public class AuthorizationObservationContext<T> extends Observation.Context {

	private Authentication authentication;

	private final T object;

	private AuthorizationDecision decision;

	public AuthorizationObservationContext(T object) {
		this.object = object;
	}

	public static <T> AuthorizationObservationContext<T> fromEvent(AuthorizationGrantedEvent<? extends T> event) {
		Supplier<Authentication> authentication = event.getAuthentication();
		T object = (T) event.getSource();
		AuthorizationObservationContext<T> context = new AuthorizationObservationContext<>(object);
		context.setName("spring.security." + event.getEventType());
		context.setAuthentication(authentication.get());
		context.setDecision(event.getAuthorizationDecision());
		return context;
	}

	public static <T> AuthorizationObservationContext<T> fromEvent(AuthorizationDeniedEvent<? extends T> event) {
		Supplier<Authentication> authentication = event.getAuthentication();
		T object = (T) event.getSource();
		AuthorizationObservationContext<T> context = new AuthorizationObservationContext<>(object);
		context.setName("spring.security." + event.getEventType());
		context.setAuthentication(authentication.get());
		context.setDecision(event.getAuthorizationDecision());
		return context;
	}

	public Authentication getAuthentication() {
		return this.authentication;
	}

	public void setAuthentication(Authentication authentication) {
		this.authentication = authentication;
	}

	public T getObject() {
		return this.object;
	}

	public AuthorizationDecision getDecision() {
		return this.decision;
	}

	public void setDecision(AuthorizationDecision decision) {
		this.decision = decision;
	}

}
