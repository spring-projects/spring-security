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

package org.springframework.security.messaging.access.intercept;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.willThrow;

@ExtendWith(MockitoExtension.class)
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

	@BeforeEach
	public void setup() {
		this.attrs = Arrays.<ConfigAttribute>asList(new SecurityConfig("ROLE_USER"));
		this.interceptor = new ChannelSecurityInterceptor(this.source);
		this.interceptor.setAccessDecisionManager(this.accessDecisionManager);
		this.interceptor.setRunAsManager(this.runAsManager);
		this.originalAuth = new TestingAuthenticationToken("user", "pass", "ROLE_USER");
		SecurityContextHolder.getContext().setAuthentication(this.originalAuth);
	}

	@AfterEach
	public void cleanup() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void constructorMessageSecurityMetadataSourceNull() {
		assertThatIllegalArgumentException().isThrownBy(() -> new ChannelSecurityInterceptor(null));
	}

	@Test
	public void getSecureObjectClass() {
		assertThat(this.interceptor.getSecureObjectClass()).isEqualTo(Message.class);
	}

	@Test
	public void obtainSecurityMetadataSource() {
		assertThat(this.interceptor.obtainSecurityMetadataSource()).isEqualTo(this.source);
	}

	@Test
	public void preSendNullAttributes() {
		assertThat(this.interceptor.preSend(this.message, this.channel)).isSameAs(this.message);
	}

	@Test
	public void preSendGrant() {
		given(this.source.getAttributes(this.message)).willReturn(this.attrs);
		Message<?> result = this.interceptor.preSend(this.message, this.channel);
		assertThat(result).isSameAs(this.message);
	}

	@Test
	public void preSendDeny() {
		given(this.source.getAttributes(this.message)).willReturn(this.attrs);
		willThrow(new AccessDeniedException("")).given(this.accessDecisionManager)
			.decide(any(Authentication.class), eq(this.message), eq(this.attrs));
		assertThatExceptionOfType(AccessDeniedException.class)
			.isThrownBy(() -> this.interceptor.preSend(this.message, this.channel));
	}

	@SuppressWarnings("unchecked")
	@Test
	public void preSendPostSendRunAs() {
		given(this.source.getAttributes(this.message)).willReturn(this.attrs);
		given(this.runAsManager.buildRunAs(any(Authentication.class), any(), any(Collection.class)))
			.willReturn(this.runAs);
		Message<?> preSend = this.interceptor.preSend(this.message, this.channel);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(this.runAs);
		this.interceptor.postSend(preSend, this.channel, true);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(this.originalAuth);
	}

	@Test
	public void afterSendCompletionNotTokenMessageNoExceptionThrown() {
		this.interceptor.afterSendCompletion(this.message, this.channel, true, null);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void preSendFinallySendRunAs() {
		given(this.source.getAttributes(this.message)).willReturn(this.attrs);
		given(this.runAsManager.buildRunAs(any(Authentication.class), any(), any(Collection.class)))
			.willReturn(this.runAs);
		Message<?> preSend = this.interceptor.preSend(this.message, this.channel);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(this.runAs);
		this.interceptor.afterSendCompletion(preSend, this.channel, true, new RuntimeException());
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(this.originalAuth);
	}

	@Test
	public void preReceive() {
		assertThat(this.interceptor.preReceive(this.channel)).isTrue();
	}

	@Test
	public void postReceive() {
		assertThat(this.interceptor.postReceive(this.message, this.channel)).isSameAs(this.message);
	}

	@Test
	public void afterReceiveCompletionNullExceptionNoExceptionThrown() {
		this.interceptor.afterReceiveCompletion(this.message, this.channel, null);
	}

}
