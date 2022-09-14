/*
 * Copyright 2002-2019 the original author or authors.
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

package org.springframework.security.oauth2.server.resource.web.reactive.function.client;

import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.Map;

import org.junit.jupiter.api.Test;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.web.MockExchangeFunction;
import org.springframework.web.reactive.function.client.ClientRequest;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link ServerBearerExchangeFilterFunction}
 *
 * @author Josh Cummings
 */
public class ServerBearerExchangeFilterFunctionTests {

	private ServerBearerExchangeFilterFunction function = new ServerBearerExchangeFilterFunction();

	private MockExchangeFunction exchange = new MockExchangeFunction();

	private OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "token-0",
			Instant.now(), Instant.now().plus(Duration.ofDays(1)));

	private Authentication authentication = new AbstractOAuth2TokenAuthenticationToken<OAuth2AccessToken>(
			this.accessToken) {
		@Override
		public Map<String, Object> getTokenAttributes() {
			return Collections.emptyMap();
		}
	};

	@Test
	public void filterWhenUnauthenticatedThenAuthorizationHeaderNull() {
		ClientRequest request = ClientRequest.create(HttpMethod.GET, URI.create("https://example.com")).build();
		this.function.filter(request, this.exchange).block();
		assertThat(this.exchange.getRequest().headers().getFirst(HttpHeaders.AUTHORIZATION)).isNull();
	}

	@Test
	public void filterWhenAuthenticatedThenAuthorizationHeaderNull() throws Exception {
		ClientRequest request = ClientRequest.create(HttpMethod.GET, URI.create("https://example.com")).build();
		this.function.filter(request, this.exchange)
				.contextWrite(ReactiveSecurityContextHolder.withAuthentication(this.authentication)).block();
		assertThat(this.exchange.getRequest().headers().getFirst(HttpHeaders.AUTHORIZATION))
				.isEqualTo("Bearer " + this.accessToken.getTokenValue());
	}

	// gh-7353
	@Test
	public void filterWhenAuthenticatedWithOtherTokenThenAuthorizationHeaderNull() throws Exception {
		ClientRequest request = ClientRequest.create(HttpMethod.GET, URI.create("https://example.com")).build();
		TestingAuthenticationToken token = new TestingAuthenticationToken("user", "pass");
		this.function.filter(request, this.exchange)
				.contextWrite(ReactiveSecurityContextHolder.withAuthentication(token)).block();
		assertThat(this.exchange.getRequest().headers().getFirst(HttpHeaders.AUTHORIZATION)).isNull();
	}

	@Test
	public void filterWhenExistingAuthorizationThenSingleAuthorizationHeader() {
		ClientRequest request = ClientRequest.create(HttpMethod.GET, URI.create("https://example.com"))
				.header(HttpHeaders.AUTHORIZATION, "Existing").build();
		this.function.filter(request, this.exchange)
				.contextWrite(ReactiveSecurityContextHolder.withAuthentication(this.authentication)).block();
		HttpHeaders headers = this.exchange.getRequest().headers();
		assertThat(headers.get(HttpHeaders.AUTHORIZATION)).containsOnly("Bearer " + this.accessToken.getTokenValue());
	}

}
