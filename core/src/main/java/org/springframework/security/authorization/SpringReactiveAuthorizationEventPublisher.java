/*
 * Copyright 2002-2023 the original author or authors.
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

import reactor.core.publisher.Mono;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authorization.event.ReactiveAuthorizationDeniedEvent;
import org.springframework.security.authorization.event.ReactiveAuthorizationGrantedEvent;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

/**
 * An implementation of {@link ReactiveAuthorizationEventPublisher} that uses Spring's
 * event publishing support. Because {@link ReactiveAuthorizationGrantedEvent}s typically
 * require additional business logic to decide whether to publish, this implementation
 * only publishes {@link ReactiveAuthorizationDeniedEvent}s.
 *
 * @author Marcus da Coregio
 * @since 6.3
 */
public class SpringReactiveAuthorizationEventPublisher implements ReactiveAuthorizationEventPublisher {

	private final ApplicationEventPublisher eventPublisher;

	/**
	 * Construct this publisher using Spring's {@link ApplicationEventPublisher}
	 * @param eventPublisher the event publisher to use
	 */
	public SpringReactiveAuthorizationEventPublisher(ApplicationEventPublisher eventPublisher) {
		Assert.notNull(eventPublisher, "eventPublisher cannot be null");
		this.eventPublisher = eventPublisher;
	}

	@Override
	public <T> void publishAuthorizationEvent(Mono<Authentication> authentication, T object,
			AuthorizationDecision decision) {
		if (decision == null || decision.isGranted()) {
			return;
		}
		this.eventPublisher.publishEvent(new ReactiveAuthorizationDeniedEvent<>(authentication, object, decision));
	}

}
