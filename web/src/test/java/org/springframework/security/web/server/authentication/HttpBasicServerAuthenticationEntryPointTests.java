/*
 * Copyright 2002-2017 the original author or authors.
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

package org.springframework.security.web.server.authentication;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.authentication.HttpBasicServerAuthenticationEntryPoint;
import org.springframework.web.server.ServerWebExchange;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verifyZeroInteractions;

/**
 * @author Rob Winch
 * @since 5.0
 */
@RunWith(MockitoJUnitRunner.class)
public class HttpBasicServerAuthenticationEntryPointTests {

	@Mock
	private ServerWebExchange exchange;

	private HttpBasicServerAuthenticationEntryPoint entryPoint = new HttpBasicServerAuthenticationEntryPoint();

	private AuthenticationException exception = new AuthenticationCredentialsNotFoundException("Authenticate");

	@Test
	public void commenceWhenNoSubscribersThenNoActions() {
		this.entryPoint.commence(this.exchange, this.exception);

		verifyZeroInteractions(this.exchange);
	}

	@Test
	public void commenceWhenSubscribeThenStatusAndHeaderSet() {
		this.exchange = exchange(MockServerHttpRequest.get("/"));

		this.entryPoint.commence(this.exchange, this.exception).block();

		assertThat(this.exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
		assertThat(this.exchange.getResponse().getHeaders().get("WWW-Authenticate"))
				.containsOnly("Basic realm=\"Realm\"");
	}

	@Test
	public void commenceWhenCustomRealmThenStatusAndHeaderSet() {
		this.entryPoint.setRealm("Custom");
		this.exchange = exchange(MockServerHttpRequest.get("/"));

		this.entryPoint.commence(this.exchange, this.exception).block();

		assertThat(this.exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
		assertThat(this.exchange.getResponse().getHeaders().get("WWW-Authenticate"))
				.containsOnly("Basic realm=\"Custom\"");
	}

	@Test(expected = IllegalArgumentException.class)
	public void setRealmWhenNullThenException() {
		this.entryPoint.setRealm(null);
	}

	private static MockServerWebExchange exchange(MockServerHttpRequest.BaseBuilder<?> request) {
		return MockServerWebExchange.from(request.build());
	}

}
