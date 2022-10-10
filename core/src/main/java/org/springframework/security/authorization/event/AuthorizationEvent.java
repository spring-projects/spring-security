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
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

/**
 * A parent class for {@link AuthorizationGrantedEvent} and
 * {@link AuthorizationDeniedEvent}.
 *
 * @author Josh Cummings
 * @since 5.8
 */
public class AuthorizationEvent extends ApplicationEvent {

	private final Supplier<Authentication> authentication;

	private final AuthorizationDecision decision;

	/**
	 * Construct an {@link AuthorizationEvent}
	 * @param authentication the principal requiring access
	 * @param object the object to which access was requested
	 * @param decision whether authorization was granted or denied
	 */
	public AuthorizationEvent(Supplier<Authentication> authentication, Object object, AuthorizationDecision decision) {
		super(object);
		Assert.notNull(authentication, "authentication supplier cannot be null");
		this.authentication = authentication;
		this.decision = decision;
	}

	/**
	 * Get the principal requiring access
	 * @return the principal requiring access
	 */
	public Supplier<Authentication> getAuthentication() {
		return this.authentication;
	}

	/**
	 * Get the object to which access was requested
	 * @return the object to which access was requested
	 */
	public Object getObject() {
		return getSource();
	}

	/**
	 * Get the response to the princpal's request
	 * @return
	 */
	public AuthorizationDecision getAuthorizationDecision() {
		return this.decision;
	}

}
