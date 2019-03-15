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
package org.springframework.security.messaging.access.intercept;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.messaging.Message;
import org.springframework.messaging.MessageChannel;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.intercept.RunAsManager;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class ChannelSecurityInterceptorTests {
	@Mock
	Message<Object> message;
	@Mock
	MessageChannel channel;
	@Mock
	MessageSecurityMetadataSource source;
	@Mock
	AccessDecisionManager accessDecisionManager;
	@Mock
	RunAsManager runAsManager;
	@Mock
	Authentication runAs;

	Authentication originalAuth;

	List<ConfigAttribute> attrs;

	ChannelSecurityInterceptor interceptor;

	@Before
	public void setup() {
		attrs = Arrays.<ConfigAttribute> asList(new SecurityConfig("ROLE_USER"));
		interceptor = new ChannelSecurityInterceptor(source);
		interceptor.setAccessDecisionManager(accessDecisionManager);
		interceptor.setRunAsManager(runAsManager);

		originalAuth = new TestingAuthenticationToken("user", "pass", "ROLE_USER");
		SecurityContextHolder.getContext().setAuthentication(originalAuth);
	}

	@After
	public void cleanup() {
		SecurityContextHolder.clearContext();
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorMessageSecurityMetadataSourceNull() {
		new ChannelSecurityInterceptor(null);
	}

	@Test
	public void getSecureObjectClass() throws Exception {
		assertThat(interceptor.getSecureObjectClass()).isEqualTo(Message.class);
	}

	@Test
	public void obtainSecurityMetadataSource() throws Exception {
		assertThat(interceptor.obtainSecurityMetadataSource()).isEqualTo(source);
	}

	@Test
	public void preSendNullAttributes() throws Exception {
		assertThat(interceptor.preSend(message, channel)).isSameAs(message);
	}

	@Test
	public void preSendGrant() throws Exception {
		when(source.getAttributes(message)).thenReturn(attrs);

		Message<?> result = interceptor.preSend(message, channel);

		assertThat(result).isSameAs(message);
	}

	@Test(expected = AccessDeniedException.class)
	public void preSendDeny() throws Exception {
		when(source.getAttributes(message)).thenReturn(attrs);
		doThrow(new AccessDeniedException("")).when(accessDecisionManager).decide(
				any(Authentication.class), eq(message), eq(attrs));

		interceptor.preSend(message, channel);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void preSendPostSendRunAs() throws Exception {
		when(source.getAttributes(message)).thenReturn(attrs);
		when(
				runAsManager.buildRunAs(any(Authentication.class), any(),
						any(Collection.class))).thenReturn(runAs);

		Message<?> preSend = interceptor.preSend(message, channel);

		assertThat(SecurityContextHolder.getContext().getAuthentication())
				.isSameAs(runAs);

		interceptor.postSend(preSend, channel, true);

		assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(
				originalAuth);
	}

	@Test
	public void afterSendCompletionNotTokenMessageNoExceptionThrown() throws Exception {
		interceptor.afterSendCompletion(message, channel, true, null);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void preSendFinallySendRunAs() throws Exception {
		when(source.getAttributes(message)).thenReturn(attrs);
		when(
				runAsManager.buildRunAs(any(Authentication.class), any(),
						any(Collection.class))).thenReturn(runAs);

		Message<?> preSend = interceptor.preSend(message, channel);

		assertThat(SecurityContextHolder.getContext().getAuthentication())
				.isSameAs(runAs);

		interceptor.afterSendCompletion(preSend, channel, true, new RuntimeException());

		assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(
				originalAuth);
	}

	@Test
	public void preReceive() throws Exception {
		assertThat(interceptor.preReceive(channel)).isTrue();
		;
	}

	@Test
	public void postReceive() throws Exception {
		assertThat(interceptor.postReceive(message, channel)).isSameAs(message);
	}

	@Test
	public void afterReceiveCompletionNullExceptionNoExceptionThrown() throws Exception {
		interceptor.afterReceiveCompletion(message, channel, null);
	}
}