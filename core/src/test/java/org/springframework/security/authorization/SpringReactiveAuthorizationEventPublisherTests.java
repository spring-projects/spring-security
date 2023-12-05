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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authentication.TestAuthentication;
import org.springframework.security.authorization.event.ReactiveAuthorizationDeniedEvent;
import org.springframework.security.core.Authentication;

import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Tests for {@link SpringReactiveAuthorizationEventPublisher}
 *
 * @author Marcus da Coregio
 */
class SpringReactiveAuthorizationEventPublisherTests {

	Mono<Authentication> authentication = Mono.just(TestAuthentication.authenticatedUser());

	ApplicationEventPublisher applicationEventPublisher;

	SpringReactiveAuthorizationEventPublisher authorizationEventPublisher;

	@BeforeEach
	void init() {
		this.applicationEventPublisher = mock(ApplicationEventPublisher.class);
		this.authorizationEventPublisher = new SpringReactiveAuthorizationEventPublisher(
				this.applicationEventPublisher);
	}

	@Test
	void testAuthenticationSuccessIsNotPublished() {
		AuthorizationDecision decision = new AuthorizationDecision(true);
		this.authorizationEventPublisher.publishAuthorizationEvent(this.authentication, mock(Object.class), decision);
		verifyNoInteractions(this.applicationEventPublisher);
	}

	@Test
	void testAuthenticationFailureIsPublished() {
		AuthorizationDecision decision = new AuthorizationDecision(false);
		this.authorizationEventPublisher.publishAuthorizationEvent(this.authentication, mock(Object.class), decision);
		verify(this.applicationEventPublisher).publishEvent(isA(ReactiveAuthorizationDeniedEvent.class));
	}

}
