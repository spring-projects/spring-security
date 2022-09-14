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

package org.springframework.security.messaging.context;

import java.security.Principal;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.messaging.MessageChannel;
import org.springframework.messaging.MessageHandler;
import org.springframework.messaging.simp.SimpMessageHeaderAccessor;
import org.springframework.messaging.support.MessageBuilder;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.context.SecurityContextImpl;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
public class SecurityContextChannelInterceptorTests {

	@Mock
	MessageChannel channel;

	@Mock
	MessageHandler handler;

	@Mock
	Principal principal;

	MessageBuilder<String> messageBuilder;

	Authentication authentication;

	SecurityContextChannelInterceptor interceptor;

	AnonymousAuthenticationToken expectedAnonymous;

	@BeforeEach
	public void setup() {
		this.authentication = new TestingAuthenticationToken("user", "pass", "ROLE_USER");
		this.messageBuilder = MessageBuilder.withPayload("payload");
		this.expectedAnonymous = new AnonymousAuthenticationToken("key", "anonymous",
				AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
		this.interceptor = new SecurityContextChannelInterceptor();
	}

	@AfterEach
	public void cleanup() {
		this.interceptor.afterMessageHandled(this.messageBuilder.build(), this.channel, this.handler, null);
		SecurityContextHolder.clearContext();
	}

	@Test
	public void constructorNullHeader() {
		assertThatIllegalArgumentException().isThrownBy(() -> new SecurityContextChannelInterceptor(null));
	}

	@Test
	public void preSendCustomHeader() {
		String headerName = "header";
		this.interceptor = new SecurityContextChannelInterceptor(headerName);
		this.messageBuilder.setHeader(headerName, this.authentication);
		this.interceptor.preSend(this.messageBuilder.build(), this.channel);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(this.authentication);
	}

	@Test
	public void preSendUserSet() {
		this.messageBuilder.setHeader(SimpMessageHeaderAccessor.USER_HEADER, this.authentication);
		this.interceptor.preSend(this.messageBuilder.build(), this.channel);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(this.authentication);
	}

	@Test
	public void preSendWhenCustomSecurityContextHolderStrategyThenUserSet() {
		SecurityContextHolderStrategy strategy = spy(SecurityContextHolder.getContextHolderStrategy());
		strategy.setContext(new SecurityContextImpl(this.authentication));
		this.interceptor.setSecurityContextHolderStrategy(strategy);
		this.messageBuilder.setHeader(SimpMessageHeaderAccessor.USER_HEADER, this.authentication);
		this.interceptor.preSend(this.messageBuilder.build(), this.channel);
		verify(strategy).getContext();
		assertThat(strategy.getContext().getAuthentication()).isSameAs(this.authentication);
	}

	@Test
	public void setAnonymousAuthenticationNull() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.interceptor.setAnonymousAuthentication(null));
	}

	@Test
	public void preSendUsesCustomAnonymous() {
		this.expectedAnonymous = new AnonymousAuthenticationToken("customKey", "customAnonymous",
				AuthorityUtils.createAuthorityList("ROLE_CUSTOM"));
		this.interceptor.setAnonymousAuthentication(this.expectedAnonymous);
		this.interceptor.preSend(this.messageBuilder.build(), this.channel);
		assertAnonymous();
	}

	// SEC-2845
	@Test
	public void preSendUserNotAuthentication() {
		this.messageBuilder.setHeader(SimpMessageHeaderAccessor.USER_HEADER, this.principal);
		this.interceptor.preSend(this.messageBuilder.build(), this.channel);
		assertAnonymous();
	}

	// SEC-2845
	@Test
	public void preSendUserNotSet() {
		this.interceptor.preSend(this.messageBuilder.build(), this.channel);
		assertAnonymous();
	}

	// SEC-2845
	@Test
	public void preSendUserNotSetCustomAnonymous() {
		this.interceptor.preSend(this.messageBuilder.build(), this.channel);
		assertAnonymous();
	}

	@Test
	public void afterSendCompletion() {
		SecurityContextHolder.getContext().setAuthentication(this.authentication);
		this.interceptor.afterSendCompletion(this.messageBuilder.build(), this.channel, true, null);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
	}

	@Test
	public void afterSendCompletionNullAuthentication() {
		this.interceptor.afterSendCompletion(this.messageBuilder.build(), this.channel, true, null);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
	}

	@Test
	public void afterSendCompletionWhenCustomSecurityContextHolderStrategyThenNullAuthentication() {
		SecurityContextHolderStrategy strategy = spy(SecurityContextHolder.getContextHolderStrategy());
		strategy.setContext(new SecurityContextImpl(this.authentication));
		this.interceptor.setSecurityContextHolderStrategy(strategy);
		this.interceptor.afterSendCompletion(this.messageBuilder.build(), this.channel, true, null);
		verify(strategy).clearContext();
		assertThat(strategy.getContext().getAuthentication()).isNull();
	}

	@Test
	public void beforeHandleUserSet() {
		this.messageBuilder.setHeader(SimpMessageHeaderAccessor.USER_HEADER, this.authentication);
		this.interceptor.beforeHandle(this.messageBuilder.build(), this.channel, this.handler);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(this.authentication);
	}

	@Test
	public void beforeHandleWhenCustomSecurityContextHolderStrategyThenUserSet() {
		SecurityContextHolderStrategy strategy = spy(SecurityContextHolder.getContextHolderStrategy());
		strategy.setContext(new SecurityContextImpl(this.authentication));
		this.interceptor.setSecurityContextHolderStrategy(strategy);
		this.messageBuilder.setHeader(SimpMessageHeaderAccessor.USER_HEADER, this.authentication);
		this.interceptor.beforeHandle(this.messageBuilder.build(), this.channel, this.handler);
		verify(strategy).getContext();
		assertThat(strategy.getContext().getAuthentication()).isSameAs(this.authentication);
	}

	// SEC-2845
	@Test
	public void beforeHandleUserNotAuthentication() {
		this.messageBuilder.setHeader(SimpMessageHeaderAccessor.USER_HEADER, this.principal);
		this.interceptor.beforeHandle(this.messageBuilder.build(), this.channel, this.handler);
		assertAnonymous();
	}

	// SEC-2845
	@Test
	public void beforeHandleUserNotSet() {
		this.interceptor.beforeHandle(this.messageBuilder.build(), this.channel, this.handler);
		assertAnonymous();
	}

	@Test
	public void afterMessageHandledUserNotSet() {
		this.interceptor.afterMessageHandled(this.messageBuilder.build(), this.channel, this.handler, null);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
	}

	@Test
	public void afterMessageHandled() {
		SecurityContextHolder.getContext().setAuthentication(this.authentication);
		this.interceptor.afterMessageHandled(this.messageBuilder.build(), this.channel, this.handler, null);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
	}

	@Test
	public void afterMessageHandledWhenCustomSecurityContextHolderStrategyThenUses() {
		SecurityContextHolderStrategy strategy = spy(SecurityContextHolder.getContextHolderStrategy());
		strategy.setContext(new SecurityContextImpl(this.authentication));
		this.interceptor.setSecurityContextHolderStrategy(strategy);
		this.interceptor.afterMessageHandled(this.messageBuilder.build(), this.channel, this.handler, null);
		verify(strategy).clearContext();
	}

	// SEC-2829
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

	/**
	 * If a user sends a websocket when processing another websocket
	 *
	 */
	@Test
	public void restoresOriginalContextNestedThreeDeep() {
		AnonymousAuthenticationToken anonymous = new AnonymousAuthenticationToken("key", "anonymous",
				AuthorityUtils.createAuthorityList("ROLE_USER"));
		TestingAuthenticationToken origional = new TestingAuthenticationToken("original", "origional", "ROLE_USER");
		SecurityContextHolder.getContext().setAuthentication(origional);
		this.messageBuilder.setHeader(SimpMessageHeaderAccessor.USER_HEADER, this.authentication);
		this.interceptor.beforeHandle(this.messageBuilder.build(), this.channel, this.handler);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(this.authentication);
		// start send websocket
		this.messageBuilder.setHeader(SimpMessageHeaderAccessor.USER_HEADER, null);
		this.interceptor.beforeHandle(this.messageBuilder.build(), this.channel, this.handler);
		assertThat(SecurityContextHolder.getContext().getAuthentication().getName()).isEqualTo(anonymous.getName());
		this.interceptor.afterMessageHandled(this.messageBuilder.build(), this.channel, this.handler, null);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(this.authentication);
		// end send websocket
		this.interceptor.afterMessageHandled(this.messageBuilder.build(), this.channel, this.handler, null);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(origional);
	}

	private void assertAnonymous() {
		Authentication currentAuthentication = SecurityContextHolder.getContext().getAuthentication();
		assertThat(currentAuthentication).isInstanceOf(AnonymousAuthenticationToken.class);
		AnonymousAuthenticationToken anonymous = (AnonymousAuthenticationToken) currentAuthentication;
		assertThat(anonymous.getName()).isEqualTo(this.expectedAnonymous.getName());
		assertThat(anonymous.getAuthorities()).containsOnlyElementsOf(this.expectedAnonymous.getAuthorities());
		assertThat(anonymous.getKeyHash()).isEqualTo(this.expectedAnonymous.getKeyHash());
	}

}
