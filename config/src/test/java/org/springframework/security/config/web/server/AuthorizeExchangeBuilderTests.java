/*
 * Copyright 2002-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
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
import org.springframework.security.test.web.reactive.server.WebTestClientBuilder;
import org.springframework.security.web.server.authorization.ExceptionTranslationWebFilter;
import org.springframework.test.web.reactive.server.WebTestClient;

/**
 * @author Rob Winch
 * @since 5.0
 */
public class AuthorizeExchangeBuilderTests {
	HttpSecurity http = HttpSecurity.http();
	HttpSecurity.AuthorizeExchangeBuilder authorization = this.http.authorizeExchange();

	@Test
	public void antMatchersWhenMethodAndPatternsThenDiscriminatesByMethod() {
		this.authorization.pathMatchers(HttpMethod.POST, "/a", "/b").denyAll();
		this.authorization.anyExchange().permitAll();

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
		this.authorization.pathMatchers("/a", "/b").denyAll();
		this.authorization.anyExchange().permitAll();

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
		this.authorization.pathMatchers("/incomplete");
		this.authorization.pathMatchers("/throws-exception");
	}

	@Test(expected = IllegalStateException.class)
	public void anyExchangeWhenFollowedByMatcherThenThrowsException() {
		this.authorization.anyExchange().denyAll();
		this.authorization.pathMatchers("/never-reached");
	}

	@Test(expected = IllegalStateException.class)
	public void buildWhenMatcherDefinedWithNoAccessThenThrowsException() {
		this.authorization.pathMatchers("/incomplete");
		this.http.build();
	}

	private WebTestClient buildClient() {
		return WebTestClientBuilder.bindToWebFilters(this.http.build()).build();
	}
}
