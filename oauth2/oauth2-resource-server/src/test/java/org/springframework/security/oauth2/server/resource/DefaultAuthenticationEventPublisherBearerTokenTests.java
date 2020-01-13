/*
 * Copyright 2002-2020 the original author or authors.
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

package org.springframework.security.oauth2.server.resource;

import org.junit.Test;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.springframework.security.oauth2.jwt.TestJwts.jwt;

/**
 * Tests for {@link DefaultAuthenticationEventPublisher}'s bearer token use cases
 *
 * {@see DefaultAuthenticationEventPublisher}
 */
public class DefaultAuthenticationEventPublisherBearerTokenTests {
	DefaultAuthenticationEventPublisher publisher;

	@Test
	public void publishAuthenticationFailureWhenInvalidBearerTokenExceptionThenMaps() {
		ApplicationEventPublisher appPublisher = mock(ApplicationEventPublisher.class);
		Authentication authentication = new JwtAuthenticationToken(jwt().build());
		Exception cause = new Exception();
		this.publisher = new DefaultAuthenticationEventPublisher(appPublisher);
		this.publisher.publishAuthenticationFailure(new InvalidBearerTokenException("invalid"), authentication);
		this.publisher.publishAuthenticationFailure(new InvalidBearerTokenException("invalid", cause), authentication);
		verify(appPublisher, times(2)).publishEvent(
				isA(AuthenticationFailureBadCredentialsEvent.class));
	}
}
