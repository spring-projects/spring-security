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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authentication.TestAuthentication;
import org.springframework.security.authorization.event.AuthorizationDeniedEvent;
import org.springframework.security.core.Authentication;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;

/**
 * Tests for {@link SpringAuthorizationEventPublisher}
 *
 * @author Parikshit Dutta
 */
public class SpringAuthorizationEventPublisherTests {

	Supplier<Authentication> authentication = TestAuthentication::authenticatedUser;

	ApplicationEventPublisher applicationEventPublisher;

	SpringAuthorizationEventPublisher authorizationEventPublisher;

	@BeforeEach
	public void init() {
		this.applicationEventPublisher = mock(ApplicationEventPublisher.class);
		this.authorizationEventPublisher = new SpringAuthorizationEventPublisher(this.applicationEventPublisher);
	}

	@Test
	public void testAuthenticationSuccessIsNotPublished() {
		AuthorizationDecision decision = new AuthorizationDecision(true);
		this.authorizationEventPublisher.publishAuthorizationEvent(this.authentication, mock(Object.class), decision);
		verifyNoInteractions(this.applicationEventPublisher);
	}

	@Test
	public void testAuthenticationFailureIsPublished() {
		AuthorizationDecision decision = new AuthorizationDecision(false);
		this.authorizationEventPublisher.publishAuthorizationEvent(this.authentication, mock(Object.class), decision);
		verify(this.applicationEventPublisher).publishEvent(isA(AuthorizationDeniedEvent.class));
	}

	@Test
	public void publishWhenPredicateMatchesThenEvent() {
		Predicate<AuthorizationResult> test = mock(Predicate.class);
		given(test.test(any())).willReturn(true, false);
		this.authorizationEventPublisher.setShouldPublishResult(test);
		AuthorizationResult result = new AuthorizationDecision(false);
		this.authorizationEventPublisher.publishAuthorizationEvent(this.authentication, mock(Object.class), result);
		verify(this.applicationEventPublisher).publishEvent(isA(AuthorizationDeniedEvent.class));
		this.authorizationEventPublisher.publishAuthorizationEvent(this.authentication, mock(Object.class), result);
		verifyNoMoreInteractions(this.applicationEventPublisher);
	}

}
