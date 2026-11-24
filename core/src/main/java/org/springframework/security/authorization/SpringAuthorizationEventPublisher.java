/*
 * Copyright 2004-present the original author or authors.
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

import java.util.function.Predicate;
import java.util.function.Supplier;

import org.jspecify.annotations.Nullable;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authorization.event.AuthorizationDeniedEvent;
import org.springframework.security.authorization.event.AuthorizationGrantedEvent;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

/**
 * An implementation of {@link AuthorizationEventPublisher} that uses Spring's event
 * publishing support.
 *
 * <p>
 * Because {@link AuthorizationGrantedEvent}s typically require additional business logic
 * to decide whether to publish, this implementation by default only publishes
 * {@link AuthorizationDeniedEvent}s. To also publish {@link AuthorizationGrantedEvent}s,
 * use {@link #setShouldPublishResult(Predicate)}.
 *
 * @author Parikshit Dutta
 * @author Josh Cummings
 * @since 5.7
 */
public final class SpringAuthorizationEventPublisher implements AuthorizationEventPublisher {

	private final ApplicationEventPublisher eventPublisher;

	private Predicate<AuthorizationResult> shouldPublishResult = (result) -> !result.isGranted();

	/**
	 * Construct this publisher using Spring's {@link ApplicationEventPublisher}.
	 * @param eventPublisher
	 */
	public SpringAuthorizationEventPublisher(ApplicationEventPublisher eventPublisher) {
		Assert.notNull(eventPublisher, "eventPublisher cannot be null");
		this.eventPublisher = eventPublisher;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public <T> void publishAuthorizationEvent(Supplier<Authentication> authentication, T object,
			@Nullable AuthorizationResult result) {
		if (result == null) {
			return;
		}
		if (!this.shouldPublishResult.test(result)) {
			return;
		}
		if (result.isGranted()) {
			this.eventPublisher.publishEvent(new AuthorizationGrantedEvent<>(authentication, object, result));
			return;
		}
		this.eventPublisher.publishEvent(new AuthorizationDeniedEvent<>(authentication, object, result));
	}

	/**
	 * Use this predicate to test whether to publish an event.
	 *
	 * <p>
	 * A granted result that passes this test is published as an
	 * {@link AuthorizationGrantedEvent}, and a denied result as an
	 * {@link AuthorizationDeniedEvent}. By default, only denied results are published.
	 *
	 * <p>
	 * Since you cannot publish a {@code null} event, checking for null is already
	 * performed before this test is run
	 * @param shouldPublishResult the test to perform on non-{@code null} events
	 * @since 7.0
	 */
	public void setShouldPublishResult(Predicate<AuthorizationResult> shouldPublishResult) {
		Assert.notNull(shouldPublishResult, "shouldPublishResult cannot be null");
		this.shouldPublishResult = shouldPublishResult;
	}

}
