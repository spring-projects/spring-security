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

package org.springframework.security.config.web.server;

import org.apache.http.HttpHeaders;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.config.annotation.web.reactive.ServerHttpSecurityConfigurationBuilder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.test.web.reactive.server.WebTestClientBuilder;
import org.springframework.security.web.server.WebFilterChainProxy;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository;
import org.springframework.test.web.reactive.server.EntityExchangeResult;
import org.springframework.test.web.reactive.server.FluxExchangeResult;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;
import reactor.test.publisher.TestPublisher;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.web.reactive.function.client.ExchangeFilterFunctions.basicAuthentication;

/**
 * @author Rob Winch
 * @since 5.0
 */
@RunWith(MockitoJUnitRunner.class)
public class ServerHttpSecurityTests {
	@Mock
	private ServerSecurityContextRepository contextRepository;
	@Mock
	private ReactiveAuthenticationManager authenticationManager;

	private ServerHttpSecurity http;

	@Before
	public void setup() {
		this.http = ServerHttpSecurityConfigurationBuilder.http()
			.authenticationManager(this.authenticationManager);
	}

	@Test
	public void defaults() {
		TestPublisher<SecurityContext> securityContext = TestPublisher.create();
		when(this.contextRepository.load(any())).thenReturn(securityContext.mono());
		this.http.securityContextRepository(this.contextRepository);

		WebTestClient client = buildClient();

		FluxExchangeResult<String> result = client.get()
			.uri("/")
			.exchange()
			.expectHeader().valueMatches(HttpHeaders.CACHE_CONTROL, ".+")
			.returnResult(String.class);

		assertThat(result.getResponseCookies()).isEmpty();
		// there is no need to try and load the SecurityContext by default
		securityContext.assertWasNotSubscribed();
	}

	@Test
	public void basic() {
		given(this.authenticationManager.authenticate(any())).willReturn(Mono.just(new TestingAuthenticationToken("rob", "rob", "ROLE_USER", "ROLE_ADMIN")));

		this.http.securityContextRepository(new WebSessionServerSecurityContextRepository());
		this.http.httpBasic();
		this.http.authenticationManager(this.authenticationManager);
		ServerHttpSecurity.AuthorizeExchangeSpec authorize = this.http.authorizeExchange();
		authorize.anyExchange().authenticated();

		WebTestClient client = buildClient();

		EntityExchangeResult<String> result = client
			.mutate()
			.filter(basicAuthentication("rob", "rob"))
			.build()
			.get()
			.uri("/")
			.exchange()
			.expectStatus().isOk()
			.expectHeader().valueMatches(HttpHeaders.CACHE_CONTROL, ".+")
			.expectBody(String.class).consumeWith(b -> assertThat(b.getResponseBody()).isEqualTo("ok"))
			.returnResult();

		assertThat(result.getResponseCookies().getFirst("SESSION")).isNull();
	}

	@Test
	public void basicWhenNoCredentialsThenUnauthorized() {
		this.http.authorizeExchange().anyExchange().authenticated();

		WebTestClient client = buildClient();
		client
			.get()
			.uri("/")
			.exchange()
			.expectStatus().isUnauthorized()
			.expectHeader().valueMatches(HttpHeaders.CACHE_CONTROL, ".+")
			.expectBody().isEmpty();
	}

	private WebTestClient buildClient() {
		WebFilterChainProxy springSecurityFilterChain = new WebFilterChainProxy(
			this.http.build());
		return WebTestClientBuilder.bindToWebFilters(springSecurityFilterChain).build();
	}
}
