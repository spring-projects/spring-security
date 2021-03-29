/*
 * Copyright 2002-2021 the original author or authors.
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

import org.junit.Before;
import org.junit.Test;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authorization.event.AuthorizationFailureEvent;
import org.springframework.security.authorization.event.AuthorizationSuccessEvent;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link DefaultAuthorizationEventPublisher}
 *
 * @author Parikshit Dutta
 */
public class DefaultAuthorizationEventPublisherTests {

	ApplicationEventPublisher applicationEventPublisher;

	DefaultAuthorizationEventPublisher authorizationEventPublisher;

	@Before
	public void init() {
		this.applicationEventPublisher = mock(ApplicationEventPublisher.class);
		this.authorizationEventPublisher = new DefaultAuthorizationEventPublisher();
		this.authorizationEventPublisher.setApplicationEventPublisher(this.applicationEventPublisher);
	}

	@Test
	public void testAuthenticationSuccessIsPublished() {
		this.authorizationEventPublisher.publishAuthorizationSuccess(mock(AuthorizationDecision.class));
		verify(this.applicationEventPublisher).publishEvent(isA(AuthorizationSuccessEvent.class));
	}

	@Test
	public void testAuthenticationFailureIsPublished() {
		this.authorizationEventPublisher.publishAuthorizationFailure(mock(AuthorizationDecision.class));
		verify(this.applicationEventPublisher).publishEvent(isA(AuthorizationFailureEvent.class));
	}

	@Test
	public void testNullPublisherNotInvoked() {
		this.authorizationEventPublisher.setApplicationEventPublisher(null);
		this.authorizationEventPublisher.publishAuthorizationSuccess(mock(AuthorizationDecision.class));
		this.authorizationEventPublisher.publishAuthorizationFailure(mock(AuthorizationDecision.class));
		verify(this.applicationEventPublisher, never()).publishEvent(any());
	}

}
