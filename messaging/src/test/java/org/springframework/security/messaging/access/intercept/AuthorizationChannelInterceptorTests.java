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

package org.springframework.security.messaging.access.intercept;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.messaging.Message;
import org.springframework.messaging.MessageChannel;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationEventPublisher;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link AuthorizationChannelInterceptor}
 */
@ExtendWith(MockitoExtension.class)
public class AuthorizationChannelInterceptorTests {

	@Mock
	Message<Object> message;

	@Mock
	MessageChannel channel;

	@Mock
	AuthorizationManager<Message<?>> authorizationManager;

	@Mock
	AuthorizationEventPublisher eventPublisher;

	Authentication originalAuth;

	AuthorizationChannelInterceptor interceptor;

	@BeforeEach
	public void setup() {
		this.interceptor = new AuthorizationChannelInterceptor(this.authorizationManager);
		this.originalAuth = new TestingAuthenticationToken("user", "pass", "ROLE_USER");
		SecurityContextHolder.getContext().setAuthentication(this.originalAuth);
	}

	@AfterEach
	public void cleanup() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void constructorWhenAuthorizationManagerNullThenIllegalArgument() {
		assertThatIllegalArgumentException().isThrownBy(() -> new AuthorizationChannelInterceptor(null));
	}

	@Test
	public void preSendWhenAllowThenSameMessage() {
		given(this.authorizationManager.check(any(), any())).willReturn(new AuthorizationDecision(true));
		assertThat(this.interceptor.preSend(this.message, this.channel)).isSameAs(this.message);
	}

	@Test
	public void preSendWhenDenyThenException() {
		given(this.authorizationManager.check(any(), any())).willReturn(new AuthorizationDecision(false));
		assertThatExceptionOfType(AccessDeniedException.class)
				.isThrownBy(() -> this.interceptor.preSend(this.message, this.channel));
	}

	@Test
	public void setEventPublisherWhenNullThenException() {
		assertThatExceptionOfType(IllegalArgumentException.class)
				.isThrownBy(() -> this.interceptor.setAuthorizationEventPublisher(null));
	}

	@Test
	public void preSendWhenAuthorizationEventPublisherThenPublishes() {
		this.interceptor.setAuthorizationEventPublisher(this.eventPublisher);
		given(this.authorizationManager.check(any(), any())).willReturn(new AuthorizationDecision(true));
		this.interceptor.preSend(this.message, this.channel);
		verify(this.eventPublisher).publishAuthorizationEvent(any(), any(), any());
	}

}
