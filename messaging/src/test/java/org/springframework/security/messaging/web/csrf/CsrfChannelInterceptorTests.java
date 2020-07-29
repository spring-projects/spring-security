/*
 * Copyright 2002-2015 the original author or authors.
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

import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import org.springframework.messaging.Message;
import org.springframework.messaging.MessageChannel;
import org.springframework.messaging.simp.SimpMessageHeaderAccessor;
import org.springframework.messaging.simp.SimpMessageType;
import org.springframework.messaging.support.MessageBuilder;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.DefaultCsrfToken;
import org.springframework.security.web.csrf.InvalidCsrfTokenException;
import org.springframework.security.web.csrf.MissingCsrfTokenException;

@RunWith(MockitoJUnitRunner.class)
public class CsrfChannelInterceptorTests {

	@Mock
	MessageChannel channel;

	SimpMessageHeaderAccessor messageHeaders;

	CsrfToken token;

	CsrfChannelInterceptor interceptor;

	@Before
	public void setup() {
		this.token = new DefaultCsrfToken("header", "param", "token");
		this.interceptor = new CsrfChannelInterceptor();

		this.messageHeaders = SimpMessageHeaderAccessor.create(SimpMessageType.CONNECT);
		this.messageHeaders.setNativeHeader(this.token.getHeaderName(), this.token.getToken());
		this.messageHeaders.setSessionAttributes(new HashMap<>());
		this.messageHeaders.getSessionAttributes().put(CsrfToken.class.getName(), this.token);
	}

	@Test
	public void preSendValidToken() {
		this.interceptor.preSend(message(), this.channel);
	}

	@Test
	public void preSendIgnoresConnectAck() {
		this.messageHeaders = SimpMessageHeaderAccessor.create(SimpMessageType.CONNECT_ACK);

		this.interceptor.preSend(message(), this.channel);
	}

	@Test
	public void preSendIgnoresDisconnect() {
		this.messageHeaders = SimpMessageHeaderAccessor.create(SimpMessageType.DISCONNECT);

		this.interceptor.preSend(message(), this.channel);
	}

	@Test
	public void preSendIgnoresDisconnectAck() {
		this.messageHeaders = SimpMessageHeaderAccessor.create(SimpMessageType.DISCONNECT_ACK);

		this.interceptor.preSend(message(), this.channel);
	}

	@Test
	public void preSendIgnoresHeartbeat() {
		this.messageHeaders = SimpMessageHeaderAccessor.create(SimpMessageType.HEARTBEAT);

		this.interceptor.preSend(message(), this.channel);
	}

	@Test
	public void preSendIgnoresMessage() {
		this.messageHeaders = SimpMessageHeaderAccessor.create(SimpMessageType.MESSAGE);

		this.interceptor.preSend(message(), this.channel);
	}

	@Test
	public void preSendIgnoresOther() {
		this.messageHeaders = SimpMessageHeaderAccessor.create(SimpMessageType.OTHER);

		this.interceptor.preSend(message(), this.channel);
	}

	@Test
	public void preSendIgnoresSubscribe() {
		this.messageHeaders = SimpMessageHeaderAccessor.create(SimpMessageType.SUBSCRIBE);

		this.interceptor.preSend(message(), this.channel);
	}

	@Test
	public void preSendIgnoresUnsubscribe() {
		this.messageHeaders = SimpMessageHeaderAccessor.create(SimpMessageType.UNSUBSCRIBE);

		this.interceptor.preSend(message(), this.channel);
	}

	@Test(expected = InvalidCsrfTokenException.class)
	public void preSendNoToken() {
		this.messageHeaders.removeNativeHeader(this.token.getHeaderName());

		this.interceptor.preSend(message(), this.channel);
	}

	@Test(expected = InvalidCsrfTokenException.class)
	public void preSendInvalidToken() {
		this.messageHeaders.setNativeHeader(this.token.getHeaderName(), this.token.getToken() + "invalid");

		this.interceptor.preSend(message(), this.channel);
	}

	@Test(expected = MissingCsrfTokenException.class)
	public void preSendMissingToken() {
		this.messageHeaders.getSessionAttributes().clear();

		this.interceptor.preSend(message(), this.channel);
	}

	@Test(expected = MissingCsrfTokenException.class)
	public void preSendMissingTokenNullSessionAttributes() {
		this.messageHeaders.setSessionAttributes(null);

		this.interceptor.preSend(message(), this.channel);
	}

	private Message<String> message() {
		Map<String, Object> headersToCopy = this.messageHeaders.toMap();
		return MessageBuilder.withPayload("hi").copyHeaders(headersToCopy).build();
	}

}
