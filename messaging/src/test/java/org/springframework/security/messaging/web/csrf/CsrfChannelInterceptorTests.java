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
import org.mockito.runners.MockitoJUnitRunner;
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
		token = new DefaultCsrfToken("header", "param", "token");
		interceptor = new CsrfChannelInterceptor();

		messageHeaders = SimpMessageHeaderAccessor.create(SimpMessageType.CONNECT);
		messageHeaders.setNativeHeader(token.getHeaderName(), token.getToken());
		messageHeaders.setSessionAttributes(new HashMap<String, Object>());
		messageHeaders.getSessionAttributes().put(CsrfToken.class.getName(), token);
	}

	@Test
	public void preSendValidToken() {
		interceptor.preSend(message(), channel);
	}

	@Test
	public void preSendIgnoresConnectAck() {
		messageHeaders = SimpMessageHeaderAccessor.create(SimpMessageType.CONNECT_ACK);

		interceptor.preSend(message(), channel);
	}

	@Test
	public void preSendIgnoresDisconnect() {
		messageHeaders = SimpMessageHeaderAccessor.create(SimpMessageType.DISCONNECT);

		interceptor.preSend(message(), channel);
	}

	@Test
	public void preSendIgnoresDisconnectAck() {
		messageHeaders = SimpMessageHeaderAccessor.create(SimpMessageType.DISCONNECT_ACK);

		interceptor.preSend(message(), channel);
	}

	@Test
	public void preSendIgnoresHeartbeat() {
		messageHeaders = SimpMessageHeaderAccessor.create(SimpMessageType.HEARTBEAT);

		interceptor.preSend(message(), channel);
	}

	@Test
	public void preSendIgnoresMessage() {
		messageHeaders = SimpMessageHeaderAccessor.create(SimpMessageType.MESSAGE);

		interceptor.preSend(message(), channel);
	}

	@Test
	public void preSendIgnoresOther() {
		messageHeaders = SimpMessageHeaderAccessor.create(SimpMessageType.OTHER);

		interceptor.preSend(message(), channel);
	}

	@Test
	public void preSendIgnoresSubscribe() {
		messageHeaders = SimpMessageHeaderAccessor.create(SimpMessageType.SUBSCRIBE);

		interceptor.preSend(message(), channel);
	}

	@Test
	public void preSendIgnoresUnsubscribe() {
		messageHeaders = SimpMessageHeaderAccessor.create(SimpMessageType.UNSUBSCRIBE);

		interceptor.preSend(message(), channel);
	}

	@Test(expected = InvalidCsrfTokenException.class)
	public void preSendNoToken() {
		messageHeaders.removeNativeHeader(token.getHeaderName());

		interceptor.preSend(message(), channel);
	}

	@Test(expected = InvalidCsrfTokenException.class)
	public void preSendInvalidToken() {
		messageHeaders.setNativeHeader(token.getHeaderName(), token.getToken()
				+ "invalid");

		interceptor.preSend(message(), channel);
	}

	@Test(expected = MissingCsrfTokenException.class)
	public void preSendMissingToken() {
		messageHeaders.getSessionAttributes().clear();

		interceptor.preSend(message(), channel);
	}

	@Test(expected = MissingCsrfTokenException.class)
	public void preSendMissingTokenNullSessionAttributes() {
		messageHeaders.setSessionAttributes(null);

		interceptor.preSend(message(), channel);
	}

	private Message<String> message() {
		Map<String, Object> headersToCopy = messageHeaders.toMap();
		return MessageBuilder.withPayload("hi").copyHeaders(headersToCopy).build();
	}
}
