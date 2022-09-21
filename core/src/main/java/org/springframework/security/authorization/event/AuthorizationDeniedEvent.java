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

package org.springframework.security.authorization.event;

import java.util.function.Supplier;

import org.springframework.context.ApplicationEvent;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.core.Authentication;
import org.springframework.security.event.FailureEvent;
import org.springframework.security.event.SecurityEvent;

/**
 * An {@link ApplicationEvent} which indicates failed authorization.
 *
 * @author Parikshit Dutta
 * @author Josh Cummings
 * @since 5.7
 */
public class AuthorizationDeniedEvent<T> extends SecurityEvent implements FailureEvent<AccessDeniedException> {

	private final Supplier<Authentication> authentication;

	private final AuthorizationDecision decision;

	private AccessDeniedException error;

	public AuthorizationDeniedEvent(Supplier<Authentication> authentication, T object, AuthorizationDecision decision) {
		super(object);
		this.authentication = authentication;
		this.decision = decision;
	}

	public Supplier<Authentication> getAuthentication() {
		return this.authentication;
	}

	public AuthorizationDecision getAuthorizationDecision() {
		return this.decision;
	}

	@Override
	public AccessDeniedException getError() {
		return this.error;
	}

	public void setError(AccessDeniedException exception) {
		this.error = exception;
	}

}
