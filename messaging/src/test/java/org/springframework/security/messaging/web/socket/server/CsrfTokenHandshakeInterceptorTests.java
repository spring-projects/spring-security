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
package org.springframework.security.messaging.web.socket.server;

import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.DefaultCsrfToken;
import org.springframework.web.socket.WebSocketHandler;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Rob Winch
 */
@RunWith(MockitoJUnitRunner.class)
public class CsrfTokenHandshakeInterceptorTests {

	@Mock
	WebSocketHandler wsHandler;

	@Mock
	ServerHttpResponse response;

	Map<String, Object> attributes;

	ServerHttpRequest request;

	MockHttpServletRequest httpRequest;

	CsrfTokenHandshakeInterceptor interceptor;

	@Before
	public void setup() {
		this.httpRequest = new MockHttpServletRequest();
		this.attributes = new HashMap<>();
		this.request = new ServletServerHttpRequest(this.httpRequest);

		this.interceptor = new CsrfTokenHandshakeInterceptor();
	}

	@Test
	public void beforeHandshakeNoAttribute() throws Exception {
		this.interceptor.beforeHandshake(this.request, this.response, this.wsHandler, this.attributes);

		assertThat(this.attributes).isEmpty();
	}

	@Test
	public void beforeHandshake() throws Exception {
		CsrfToken token = new DefaultCsrfToken("header", "param", "token");
		this.httpRequest.setAttribute(CsrfToken.class.getName(), token);

		this.interceptor.beforeHandshake(this.request, this.response, this.wsHandler, this.attributes);

		assertThat(this.attributes.keySet()).containsOnly(CsrfToken.class.getName());
		assertThat(this.attributes.values()).containsOnly(token);
	}

}
