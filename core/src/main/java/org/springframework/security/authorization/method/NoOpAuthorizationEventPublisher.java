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

package org.springframework.security.authorization.method;

import java.util.function.Supplier;

import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationEventPublisher;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.core.Authentication;

/**
 * An {@link AuthorizationEventPublisher} implementation that does nothing.
 *
 * @author Max Batischev
 * @since 6.4
 */
final class NoOpAuthorizationEventPublisher implements AuthorizationEventPublisher {

	@Override
	public <T> void publishAuthorizationEvent(Supplier<Authentication> authentication, T object,
			AuthorizationDecision decision) {
	}

	@Override
	public <T> void publishAuthorizationEvent(Supplier<Authentication> authentication, T object,
			AuthorizationResult result) {

	}

}
