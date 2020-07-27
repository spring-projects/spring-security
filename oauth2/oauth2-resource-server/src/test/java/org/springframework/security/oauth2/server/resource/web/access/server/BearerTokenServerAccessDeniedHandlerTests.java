/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.oauth2.server.resource.web.access.server;

import java.util.Arrays;
import java.util.Collections;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import reactor.core.publisher.Mono;

import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken;
import org.springframework.web.server.ServerWebExchange;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

public class BearerTokenServerAccessDeniedHandlerTests {

	private BearerTokenServerAccessDeniedHandler accessDeniedHandler;

	@Before
	public void setUp() {
		this.accessDeniedHandler = new BearerTokenServerAccessDeniedHandler();
	}

	@Test
	public void handleWhenNotOAuth2AuthenticatedThenStatus403() {

		Authentication token = new TestingAuthenticationToken("user", "pass");
		ServerWebExchange exchange = mock(ServerWebExchange.class);
		given(exchange.getPrincipal()).willReturn(Mono.just(token));
		given(exchange.getResponse()).willReturn(new MockServerHttpResponse());

		this.accessDeniedHandler.handle(exchange, null).block();

		assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
		assertThat(exchange.getResponse().getHeaders().get("WWW-Authenticate")).isEqualTo(Arrays.asList("Bearer"));
	}

	@Test
	public void handleWhenNotOAuth2AuthenticatedAndRealmSetThenStatus403AndAuthHeaderWithRealm() {

		Authentication token = new TestingAuthenticationToken("user", "pass");
		ServerWebExchange exchange = mock(ServerWebExchange.class);
		given(exchange.getPrincipal()).willReturn(Mono.just(token));
		given(exchange.getResponse()).willReturn(new MockServerHttpResponse());

		this.accessDeniedHandler.setRealmName("test");
		this.accessDeniedHandler.handle(exchange, null).block();

		assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
		assertThat(exchange.getResponse().getHeaders().get("WWW-Authenticate"))
				.isEqualTo(Arrays.asList("Bearer realm=\"test\""));
	}

	@Test
	public void handleWhenOAuth2AuthenticatedThenStatus403AndAuthHeaderWithInsufficientScopeErrorAttribute() {

		Authentication token = new TestingOAuth2TokenAuthenticationToken(Collections.emptyMap());
		ServerWebExchange exchange = mock(ServerWebExchange.class);
		given(exchange.getPrincipal()).willReturn(Mono.just(token));
		given(exchange.getResponse()).willReturn(new MockServerHttpResponse());

		this.accessDeniedHandler.handle(exchange, null).block();

		assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
		assertThat(exchange.getResponse().getHeaders().get("WWW-Authenticate"))
				.isEqualTo(Arrays.asList("Bearer error=\"insufficient_scope\", "
						+ "error_description=\"The request requires higher privileges than provided by the access token.\", "
						+ "error_uri=\"https://tools.ietf.org/html/rfc6750#section-3.1\""));
	}

	@Test
	public void setRealmNameWhenNullRealmNameThenNoExceptionThrown() {
		assertThatCode(() -> this.accessDeniedHandler.setRealmName(null)).doesNotThrowAnyException();
	}

	static class TestingOAuth2TokenAuthenticationToken
			extends AbstractOAuth2TokenAuthenticationToken<TestingOAuth2TokenAuthenticationToken.TestingOAuth2Token> {

		private Map<String, Object> attributes;

		protected TestingOAuth2TokenAuthenticationToken(Map<String, Object> attributes) {
			super(new TestingOAuth2TokenAuthenticationToken.TestingOAuth2Token("token"));
			this.attributes = attributes;
		}

		@Override
		public Map<String, Object> getTokenAttributes() {
			return this.attributes;
		}

		static class TestingOAuth2Token extends AbstractOAuth2Token {

			TestingOAuth2Token(String tokenValue) {
				super(tokenValue);
			}

		}

	}

}
