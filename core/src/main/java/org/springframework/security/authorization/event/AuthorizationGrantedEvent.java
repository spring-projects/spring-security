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

/**
 * An {@link ApplicationEvent} which indicates successful authorization.
 *
 * @author Parikshit Dutta
 * @author Josh Cummings
 * @since 5.7
 */
public class AuthorizationGrantedEvent<T> extends AuthorizationEvent {

	public AuthorizationGrantedEvent(Supplier<Authentication> authentication, T object,
			AuthorizationDecision decision) {
		super(authentication, object, decision);
	}

	/**
	 * Get the object to which access was requested
	 * @return the object to which access was requested
	 * @since 5.8
	 */
	@Override
	@SuppressWarnings("unchecked")
	public T getObject() {
		return (T) getSource();
	}

}
