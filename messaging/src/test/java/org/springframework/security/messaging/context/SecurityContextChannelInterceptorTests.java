/*
 * Copyright 2002-2016 the original author or authors.
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

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import org.springframework.messaging.MessageChannel;
import org.springframework.messaging.MessageHandler;
import org.springframework.messaging.simp.SimpMessageHeaderAccessor;
import org.springframework.messaging.support.MessageBuilder;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.core.context.SecurityContextHolder.clearContext;

@RunWith(MockitoJUnitRunner.class)
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

	@Before
	public void setup() {
		this.authentication = new TestingAuthenticationToken("user", "pass", "ROLE_USER");
		this.messageBuilder = MessageBuilder.withPayload("payload");
		this.expectedAnonymous = new AnonymousAuthenticationToken("key", "anonymous",
				AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));

		this.interceptor = new SecurityContextChannelInterceptor();
	}

	@After
	public void cleanup() {
		clearContext();
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorNullHeader() {
		new SecurityContextChannelInterceptor(null);
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

	@Test(expected = IllegalArgumentException.class)
	public void setAnonymousAuthenticationNull() {
		this.interceptor.setAnonymousAuthentication(null);
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
	public void beforeHandleUserSet() {
		this.messageBuilder.setHeader(SimpMessageHeaderAccessor.USER_HEADER, this.authentication);

		this.interceptor.beforeHandle(this.messageBuilder.build(), this.channel, this.handler);

		assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(this.authentication);
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
