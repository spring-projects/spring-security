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

package org.springframework.security.messaging.context;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.messaging.Message;
import org.springframework.messaging.MessageChannel;
import org.springframework.messaging.MessageHandler;
import org.springframework.messaging.simp.SimpMessageHeaderAccessor;
import org.springframework.messaging.support.MessageBuilder;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.context.SecurityContextImpl;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
public class SecurityContextPropagationChannelInterceptorTests {

	@Mock
	MessageChannel channel;

	@Mock
	MessageHandler handler;

	MessageBuilder<String> messageBuilder;

	Authentication authentication;

	SecurityContextPropagationChannelInterceptor interceptor;

	@BeforeEach
	public void setup() {
		this.authentication = new TestingAuthenticationToken("user", "pass", "ROLE_USER");
		this.messageBuilder = MessageBuilder.withPayload("payload");
		this.interceptor = new SecurityContextPropagationChannelInterceptor();
	}

	@AfterEach
	public void cleanup() {
		this.interceptor.afterMessageHandled(this.messageBuilder.build(), this.channel, this.handler, null);
		SecurityContextHolder.clearContext();
	}

	@Test
	public void preSendDefaultHeader() {
		SecurityContextHolder.getContext().setAuthentication(this.authentication);
		Message<?> message = this.interceptor.preSend(this.messageBuilder.build(), this.channel);
		assertThat(message.getHeaders()).containsEntry(SimpMessageHeaderAccessor.USER_HEADER, this.authentication);
	}

	@Test
	public void preSendCustomHeader() {
		SecurityContextHolder.getContext().setAuthentication(this.authentication);
		String headerName = "header";
		this.interceptor = new SecurityContextPropagationChannelInterceptor(headerName);
		Message<?> message = this.interceptor.preSend(this.messageBuilder.build(), this.channel);
		assertThat(message.getHeaders()).containsEntry(headerName, this.authentication);
	}

	@Test
	public void preSendWhenCustomSecurityContextHolderStrategyThenUserSet() {
		SecurityContextHolderStrategy strategy = spy(SecurityContextHolder.getContextHolderStrategy());
		strategy.setContext(new SecurityContextImpl(this.authentication));
		this.interceptor.setSecurityContextHolderStrategy(strategy);
		Message<?> message = this.interceptor.preSend(this.messageBuilder.build(), this.channel);
		this.interceptor.beforeHandle(message, this.channel, this.handler);
		verify(strategy, times(2)).getContext();
		assertThat(strategy.getContext().getAuthentication()).isSameAs(this.authentication);
	}

	@Test
	public void preSendUserNoContext() {
		Message<?> message = this.interceptor.preSend(this.messageBuilder.build(), this.channel);
		assertThat(message.getHeaders()).containsKey(SimpMessageHeaderAccessor.USER_HEADER);
		assertThat(message.getHeaders().get(SimpMessageHeaderAccessor.USER_HEADER))
			.isInstanceOf(AnonymousAuthenticationToken.class);
	}

	@Test
	public void beforeHandleUserSet() {
		this.messageBuilder.setHeader(SimpMessageHeaderAccessor.USER_HEADER, this.authentication);
		this.interceptor.beforeHandle(this.messageBuilder.build(), this.channel, this.handler);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(this.authentication);
	}

	@Test
	public void postReceiveUserSet() {
		this.messageBuilder.setHeader(SimpMessageHeaderAccessor.USER_HEADER, this.authentication);
		this.interceptor.postReceive(this.messageBuilder.build(), this.channel);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(this.authentication);
	}

	@Test
	public void authenticationIsPropagatedFromPreSendToPostReceive() {
		SecurityContextHolder.getContext().setAuthentication(this.authentication);
		Message<?> message = this.interceptor.preSend(this.messageBuilder.build(), this.channel);
		assertThat(message.getHeaders().get(SimpMessageHeaderAccessor.USER_HEADER)).isSameAs(this.authentication);
		this.interceptor.postReceive(message, this.channel);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(this.authentication);
	}

	@Test
	public void beforeHandleUserNotSet() {
		this.interceptor.beforeHandle(this.messageBuilder.build(), this.channel, this.handler);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
	}

	@Test
	public void afterMessageHandledUserNotSet() {
		this.interceptor.afterMessageHandled(this.messageBuilder.build(), this.channel, this.handler, null);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
	}

	@Test
	public void afterMessageHandled() {
		SecurityContextHolder.getContext().setAuthentication(this.authentication);
		this.messageBuilder.setHeader(SimpMessageHeaderAccessor.USER_HEADER, this.authentication);
		this.interceptor.afterMessageHandled(this.messageBuilder.build(), this.channel, this.handler, null);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
	}

	@Test
	public void restoresOriginalContext() {
		TestingAuthenticationToken original = new TestingAuthenticationToken("original", "original", "ROLE_USER");
		SecurityContextHolder.getContext().setAuthentication(original);
		this.messageBuilder.setHeader(SimpMessageHeaderAccessor.USER_HEADER, this.authentication);
		this.interceptor.beforeHandle(this.messageBuilder.build(), this.channel, this.handler);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(this.authentication);
		this.interceptor.afterMessageHandled(this.messageBuilder.build(), this.channel, this.handler, null);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(original);
	}

}
