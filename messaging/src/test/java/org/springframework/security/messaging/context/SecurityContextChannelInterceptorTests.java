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
		authentication = new TestingAuthenticationToken("user", "pass", "ROLE_USER");
		messageBuilder = MessageBuilder.withPayload("payload");
		expectedAnonymous = new AnonymousAuthenticationToken("key", "anonymous",
				AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));

		interceptor = new SecurityContextChannelInterceptor();
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
		interceptor = new SecurityContextChannelInterceptor(headerName);
		messageBuilder.setHeader(headerName, authentication);

		interceptor.preSend(messageBuilder.build(), channel);

		assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(authentication);
	}

	@Test
	public void preSendUserSet() {
		messageBuilder.setHeader(SimpMessageHeaderAccessor.USER_HEADER, authentication);

		interceptor.preSend(messageBuilder.build(), channel);

		assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(authentication);
	}

	@Test(expected = IllegalArgumentException.class)
	public void setAnonymousAuthenticationNull() {
		interceptor.setAnonymousAuthentication(null);
	}

	@Test
	public void preSendUsesCustomAnonymous() {
		expectedAnonymous = new AnonymousAuthenticationToken("customKey", "customAnonymous",
				AuthorityUtils.createAuthorityList("ROLE_CUSTOM"));
		interceptor.setAnonymousAuthentication(expectedAnonymous);

		interceptor.preSend(messageBuilder.build(), channel);

		assertAnonymous();
	}

	// SEC-2845
	@Test
	public void preSendUserNotAuthentication() {
		messageBuilder.setHeader(SimpMessageHeaderAccessor.USER_HEADER, principal);

		interceptor.preSend(messageBuilder.build(), channel);

		assertAnonymous();
	}

	// SEC-2845
	@Test
	public void preSendUserNotSet() {
		interceptor.preSend(messageBuilder.build(), channel);

		assertAnonymous();
	}

	// SEC-2845
	@Test
	public void preSendUserNotSetCustomAnonymous() {
		interceptor.preSend(messageBuilder.build(), channel);

		assertAnonymous();
	}

	@Test
	public void afterSendCompletion() {
		SecurityContextHolder.getContext().setAuthentication(authentication);

		interceptor.afterSendCompletion(messageBuilder.build(), channel, true, null);

		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
	}

	@Test
	public void afterSendCompletionNullAuthentication() {
		interceptor.afterSendCompletion(messageBuilder.build(), channel, true, null);

		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
	}

	@Test
	public void beforeHandleUserSet() {
		messageBuilder.setHeader(SimpMessageHeaderAccessor.USER_HEADER, authentication);

		interceptor.beforeHandle(messageBuilder.build(), channel, handler);

		assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(authentication);
	}

	// SEC-2845
	@Test
	public void beforeHandleUserNotAuthentication() {
		messageBuilder.setHeader(SimpMessageHeaderAccessor.USER_HEADER, principal);

		interceptor.beforeHandle(messageBuilder.build(), channel, handler);

		assertAnonymous();
	}

	// SEC-2845
	@Test
	public void beforeHandleUserNotSet() {
		interceptor.beforeHandle(messageBuilder.build(), channel, handler);

		assertAnonymous();
	}

	@Test
	public void afterMessageHandledUserNotSet() {
		interceptor.afterMessageHandled(messageBuilder.build(), channel, handler, null);

		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
	}

	@Test
	public void afterMessageHandled() {
		SecurityContextHolder.getContext().setAuthentication(authentication);

		interceptor.afterMessageHandled(messageBuilder.build(), channel, handler, null);

		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
	}

	// SEC-2829
	@Test
	public void restoresOriginalContext() {
		TestingAuthenticationToken original = new TestingAuthenticationToken("original", "original", "ROLE_USER");
		SecurityContextHolder.getContext().setAuthentication(original);

		messageBuilder.setHeader(SimpMessageHeaderAccessor.USER_HEADER, authentication);
		interceptor.beforeHandle(messageBuilder.build(), channel, handler);

		assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(authentication);

		interceptor.afterMessageHandled(messageBuilder.build(), channel, handler, null);

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

		messageBuilder.setHeader(SimpMessageHeaderAccessor.USER_HEADER, authentication);
		interceptor.beforeHandle(messageBuilder.build(), channel, handler);

		assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(authentication);

		// start send websocket
		messageBuilder.setHeader(SimpMessageHeaderAccessor.USER_HEADER, null);
		interceptor.beforeHandle(messageBuilder.build(), channel, handler);

		assertThat(SecurityContextHolder.getContext().getAuthentication().getName()).isEqualTo(anonymous.getName());

		interceptor.afterMessageHandled(messageBuilder.build(), channel, handler, null);

		assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(authentication);
		// end send websocket

		interceptor.afterMessageHandled(messageBuilder.build(), channel, handler, null);

		assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(origional);
	}

	private void assertAnonymous() {
		Authentication currentAuthentication = SecurityContextHolder.getContext().getAuthentication();
		assertThat(currentAuthentication).isInstanceOf(AnonymousAuthenticationToken.class);

		AnonymousAuthenticationToken anonymous = (AnonymousAuthenticationToken) currentAuthentication;
		assertThat(anonymous.getName()).isEqualTo(expectedAnonymous.getName());
		assertThat(anonymous.getAuthorities()).containsOnlyElementsOf(expectedAnonymous.getAuthorities());
		assertThat(anonymous.getKeyHash()).isEqualTo(expectedAnonymous.getKeyHash());
	}

}
