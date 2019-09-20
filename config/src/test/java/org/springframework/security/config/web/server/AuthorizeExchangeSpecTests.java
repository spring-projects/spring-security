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

package org.springframework.security.config.web.server;

import org.junit.Test;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.reactive.ServerHttpSecurityConfigurationBuilder;
import org.springframework.security.test.web.reactive.server.WebTestClientBuilder;
import org.springframework.test.web.reactive.server.WebTestClient;

/**
 * @author Rob Winch
 * @since 5.0
 */
public class AuthorizeExchangeSpecTests {
	ServerHttpSecurity http = ServerHttpSecurityConfigurationBuilder.httpWithDefaultAuthentication();

	@Test
	public void antMatchersWhenMethodAndPatternsThenDiscriminatesByMethod() {
		this.http
			.csrf().disable()
			.authorizeExchange()
				.pathMatchers(HttpMethod.POST, "/a", "/b").denyAll()
				.anyExchange().permitAll();

		WebTestClient client = buildClient();

		client.get()
			.uri("/a")
			.exchange()
			.expectStatus().isOk();

		client.get()
			.uri("/b")
			.exchange()
			.expectStatus().isOk();

		client.post()
			.uri("/a")
			.exchange()
			.expectStatus().isUnauthorized();

		client.post()
			.uri("/b")
			.exchange()
			.expectStatus().isUnauthorized();
	}


	@Test
	public void antMatchersWhenPatternsThenAnyMethod() {
		this.http
			.csrf().disable()
			.authorizeExchange()
				.pathMatchers("/a", "/b").denyAll()
				.anyExchange().permitAll();

		WebTestClient client = buildClient();

		client.get()
			.uri("/a")
			.exchange()
			.expectStatus().isUnauthorized();

		client.get()
			.uri("/b")
			.exchange()
			.expectStatus().isUnauthorized();

		client.post()
			.uri("/a")
			.exchange()
			.expectStatus().isUnauthorized();

		client.post()
			.uri("/b")
			.exchange()
			.expectStatus().isUnauthorized();
	}

	@Test
	public void antMatchersWhenPatternsInLambdaThenAnyMethod() {
		this.http
			.csrf(ServerHttpSecurity.CsrfSpec::disable)
			.authorizeExchange(exchanges ->
				exchanges
					.pathMatchers("/a", "/b").denyAll()
					.anyExchange().permitAll()
			);

		WebTestClient client = buildClient();

		client.get()
			.uri("/a")
			.exchange()
			.expectStatus().isUnauthorized();

		client.get()
			.uri("/b")
			.exchange()
			.expectStatus().isUnauthorized();

		client.post()
			.uri("/a")
			.exchange()
			.expectStatus().isUnauthorized();

		client.post()
			.uri("/b")
			.exchange()
			.expectStatus().isUnauthorized();
	}

	@Test(expected = IllegalStateException.class)
	public void antMatchersWhenNoAccessAndAnotherMatcherThenThrowsException() {
		this.http
			.authorizeExchange()
				.pathMatchers("/incomplete");
		this.http
			.authorizeExchange()
				.pathMatchers("/throws-exception");
	}

	@Test(expected = IllegalStateException.class)
	public void anyExchangeWhenFollowedByMatcherThenThrowsException() {
		this.http
			.authorizeExchange().anyExchange().denyAll()
			.pathMatchers("/never-reached");
	}

	@Test(expected = IllegalStateException.class)
	public void buildWhenMatcherDefinedWithNoAccessThenThrowsException() {
		this.http
			.authorizeExchange()
				.pathMatchers("/incomplete");
		this.http.build();
	}

	@Test(expected = IllegalStateException.class)
	public void buildWhenMatcherDefinedWithNoAccessInLambdaThenThrowsException() {
		this.http
			.authorizeExchange(exchanges ->
				exchanges
					.pathMatchers("/incomplete")
			);
		this.http.build();
	}

	private WebTestClient buildClient() {
		return WebTestClientBuilder.bindToWebFilters(this.http.build()).build();
	}
}
