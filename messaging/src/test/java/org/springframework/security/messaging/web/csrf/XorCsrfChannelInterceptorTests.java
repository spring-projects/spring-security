/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.messaging.web.csrf;

import java.util.Base64;
import java.util.HashMap;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.messaging.Message;
import org.springframework.messaging.MessageChannel;
import org.springframework.messaging.simp.SimpMessageHeaderAccessor;
import org.springframework.messaging.simp.SimpMessageType;
import org.springframework.messaging.support.MessageBuilder;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.DefaultCsrfToken;
import org.springframework.security.web.csrf.InvalidCsrfTokenException;
import org.springframework.security.web.csrf.MissingCsrfTokenException;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link XorCsrfChannelInterceptor}.
 *
 * @author Steve Riesenberg
 */
public class XorCsrfChannelInterceptorTests {

	private static final String XOR_CSRF_TOKEN_VALUE = "wpe7zB62-NCpcA==";

	private static final String INVALID_XOR_CSRF_TOKEN_VALUE = "KneoaygbRZtfHQ==";

	private CsrfToken token;

	private SimpMessageHeaderAccessor messageHeaders;

	private MessageChannel channel;

	private XorCsrfChannelInterceptor interceptor;

	@BeforeEach
	public void setup() {
		this.token = new DefaultCsrfToken("header", "param", "token");
		this.messageHeaders = SimpMessageHeaderAccessor.create(SimpMessageType.CONNECT);
		this.messageHeaders.setSessionAttributes(new HashMap<>());
		this.channel = mock(MessageChannel.class);
		this.interceptor = new XorCsrfChannelInterceptor();
	}

	@Test
	public void preSendWhenConnectWithValidTokenThenSuccess() {
		this.messageHeaders.setNativeHeader(this.token.getHeaderName(), XOR_CSRF_TOKEN_VALUE);
		this.messageHeaders.getSessionAttributes().put(CsrfToken.class.getName(), this.token);
		this.interceptor.preSend(message(), this.channel);
	}

	@Test
	public void preSendWhenConnectWithInvalidTokenThenThrowsInvalidCsrfTokenException() {
		this.messageHeaders.setNativeHeader(this.token.getHeaderName(), INVALID_XOR_CSRF_TOKEN_VALUE);
		this.messageHeaders.getSessionAttributes().put(CsrfToken.class.getName(), this.token);
		// @formatter:off
		assertThatExceptionOfType(InvalidCsrfTokenException.class)
				.isThrownBy(() -> this.interceptor.preSend(message(), mock(MessageChannel.class)));
		// @formatter:on
	}

	@Test
	public void preSendWhenConnectWithNoTokenThenThrowsInvalidCsrfTokenException() {
		this.messageHeaders.getSessionAttributes().put(CsrfToken.class.getName(), this.token);
		// @formatter:off
		assertThatExceptionOfType(InvalidCsrfTokenException.class)
				.isThrownBy(() -> this.interceptor.preSend(message(), mock(MessageChannel.class)));
		// @formatter:on
	}

	@Test
	public void preSendWhenConnectWithMissingTokenThenThrowsMissingCsrfTokenException() {
		// @formatter:off
		assertThatExceptionOfType(MissingCsrfTokenException.class)
				.isThrownBy(() -> this.interceptor.preSend(message(), mock(MessageChannel.class)));
		// @formatter:on
	}

	@Test
	public void preSendWhenConnectWithNullSessionAttributesThenThrowsMissingCsrfTokenException() {
		this.messageHeaders.setSessionAttributes(null);
		// @formatter:off
		assertThatExceptionOfType(MissingCsrfTokenException.class)
				.isThrownBy(() -> this.interceptor.preSend(message(), mock(MessageChannel.class)));
		// @formatter:on
	}

	@Test
	public void preSendWhenAckThenIgnores() {
		this.messageHeaders = SimpMessageHeaderAccessor.create(SimpMessageType.CONNECT_ACK);
		this.interceptor.preSend(message(), this.channel);
	}

	@Test
	public void preSendWhenDisconnectThenIgnores() {
		this.messageHeaders = SimpMessageHeaderAccessor.create(SimpMessageType.DISCONNECT);
		this.interceptor.preSend(message(), this.channel);
	}

	@Test
	public void preSendWhenHeartbeatThenIgnores() {
		this.messageHeaders = SimpMessageHeaderAccessor.create(SimpMessageType.HEARTBEAT);
		this.interceptor.preSend(message(), this.channel);
	}

	@Test
	public void preSendWhenMessageThenIgnores() {
		this.messageHeaders = SimpMessageHeaderAccessor.create(SimpMessageType.MESSAGE);
		this.interceptor.preSend(message(), this.channel);
	}

	@Test
	public void preSendWhenOtherThenIgnores() {
		this.messageHeaders = SimpMessageHeaderAccessor.create(SimpMessageType.OTHER);
		this.interceptor.preSend(message(), this.channel);
	}

	@Test
	public void preSendWhenUnsubscribeThenIgnores() {
		this.messageHeaders = SimpMessageHeaderAccessor.create(SimpMessageType.UNSUBSCRIBE);
		this.interceptor.preSend(message(), this.channel);
	}

	// gh-13310, gh-15184
	@Test
	public void preSendWhenCsrfBytesIsShorterThanRandomBytesThenThrowsInvalidCsrfTokenException() {
		/*
		 * Token format: 3 random pad bytes + 2 padded bytes.
		 */
		byte[] actualBytes = { 1, 1, 1, 96, 99 };
		String actualToken = Base64.getEncoder().encodeToString(actualBytes);
		this.messageHeaders.setNativeHeader(this.token.getHeaderName(), actualToken);
		this.messageHeaders.getSessionAttributes().put(CsrfToken.class.getName(), this.token);
		// @formatter:off
		assertThatExceptionOfType(InvalidCsrfTokenException.class)
				.isThrownBy(() -> this.interceptor.preSend(message(), mock(MessageChannel.class)));
		// @formatter:on
	}

	// gh-13310, gh-15184
	@Test
	public void preSendWhenCsrfBytesIsLongerThanRandomBytesThenThrowsInvalidCsrfTokenException() {
		/*
		 * Token format: 3 random pad bytes + 4 padded bytes.
		 */
		byte[] actualBytes = { 1, 1, 1, 96, 99, 98, 97 };
		String actualToken = Base64.getEncoder().encodeToString(actualBytes);
		this.messageHeaders.setNativeHeader(this.token.getHeaderName(), actualToken);
		this.messageHeaders.getSessionAttributes().put(CsrfToken.class.getName(), this.token);
		// @formatter:off
		assertThatExceptionOfType(InvalidCsrfTokenException.class)
				.isThrownBy(() -> this.interceptor.preSend(message(), mock(MessageChannel.class)));
		// @formatter:on
	}

	// gh-13310, gh-15184
	@Test
	public void preSendWhenTokenBytesIsShorterThanActualBytesThenThrowsInvalidCsrfTokenException() {
		this.messageHeaders.setNativeHeader(this.token.getHeaderName(), XOR_CSRF_TOKEN_VALUE);
		CsrfToken csrfToken = new DefaultCsrfToken("header", "param", "a");
		this.messageHeaders.getSessionAttributes().put(CsrfToken.class.getName(), csrfToken);
		// @formatter:off
		assertThatExceptionOfType(InvalidCsrfTokenException.class)
				.isThrownBy(() -> this.interceptor.preSend(message(), mock(MessageChannel.class)));
		// @formatter:on
	}

	// gh-13310, gh-15184
	@Test
	public void preSendWhenTokenBytesIsLongerThanActualBytesThenThrowsInvalidCsrfTokenException() {
		this.messageHeaders.setNativeHeader(this.token.getHeaderName(), XOR_CSRF_TOKEN_VALUE);
		CsrfToken csrfToken = new DefaultCsrfToken("header", "param", "abcde");
		this.messageHeaders.getSessionAttributes().put(CsrfToken.class.getName(), csrfToken);
		// @formatter:off
		assertThatExceptionOfType(InvalidCsrfTokenException.class)
				.isThrownBy(() -> this.interceptor.preSend(message(), mock(MessageChannel.class)));
		// @formatter:on
	}

	// gh-13310, gh-15184
	@Test
	public void preSendWhenActualBytesIsEmptyThenThrowsInvalidCsrfTokenException() {
		this.messageHeaders.setNativeHeader(this.token.getHeaderName(), "");
		this.messageHeaders.getSessionAttributes().put(CsrfToken.class.getName(), this.token);
		// @formatter:off
		assertThatExceptionOfType(InvalidCsrfTokenException.class)
				.isThrownBy(() -> this.interceptor.preSend(message(), mock(MessageChannel.class)));
		// @formatter:on
	}

	private Message<String> message() {
		return MessageBuilder.withPayload("message").copyHeaders(this.messageHeaders.toMap()).build();
	}

}
