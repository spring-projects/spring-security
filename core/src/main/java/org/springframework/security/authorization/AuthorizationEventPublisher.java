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

import org.springframework.security.authorization.event.AuthorizationDeniedEvent;
import org.springframework.security.authorization.event.AuthorizationGrantedEvent;
import org.springframework.security.core.Authentication;

/**
 * A contract for publishing authorization events
 *
 * @author Parikshit Dutta
 * @author Josh Cummings
 * @since 5.7
 * @see AuthorizationManager
 */
public interface AuthorizationEventPublisher {

	/**
	 * Publish the given details in the form of an event, typically
	 * {@link AuthorizationGrantedEvent} or {@link AuthorizationDeniedEvent}.
	 *
	 * Note that success events can be very noisy if enabled by default. Because of this
	 * implementations may choose to drop success events by default.
	 * @param authentication a {@link Supplier} for the current user
	 * @param object the secured object
	 * @param decision the decision about whether the user may access the secured object
	 * @param <T> the secured object's type
	 */
	<T> void publishAuthorizationEvent(Supplier<Authentication> authentication, T object,
			AuthorizationDecision decision);

}
