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

import org.apache.http.HttpHeaders;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.test.web.reactive.server.WebTestClientBuilder;
import org.springframework.security.web.server.WebFilterChainFilter;
import org.springframework.security.web.server.context.SecurityContextRepository;
import org.springframework.security.web.server.context.WebSessionSecurityContextRepository;
import org.springframework.test.web.reactive.server.EntityExchangeResult;
import org.springframework.test.web.reactive.server.FluxExchangeResult;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.springframework.web.reactive.function.client.ExchangeFilterFunctions.basicAuthentication;

/**
 * @author Rob Winch
 * @since 5.0
 */
@RunWith(MockitoJUnitRunner.class)
public class HttpSecurityTests {
	@Mock
	SecurityContextRepository contextRepository;
	@Mock
	ReactiveAuthenticationManager authenticationManager;

	HttpSecurity http;

	@Before
	public void setup() {
		this.http = HttpSecurity.http().headers().and();
	}

	@Test
	public void defaults() {
		this.http.securityContextRepository(this.contextRepository);

		WebTestClient client = buildClient();

		FluxExchangeResult<String> result = client.get()
			.uri("/")
			.exchange()
			.expectHeader().valueMatches(HttpHeaders.CACHE_CONTROL, ".+")
			.returnResult(String.class);

		assertThat(result.getResponseCookies()).isEmpty();
		// there is no need to try and load the SecurityContext by default
		verifyZeroInteractions(this.contextRepository);
	}

	@Test
	public void basic() {
		given(this.authenticationManager.authenticate(any())).willReturn(Mono.just(new TestingAuthenticationToken("rob", "rob", "ROLE_USER", "ROLE_ADMIN")));

		this.http.securityContextRepository(new WebSessionSecurityContextRepository());
		this.http.httpBasic();
		this.http.authenticationManager(this.authenticationManager);
		HttpSecurity.AuthorizeExchangeBuilder authorize = this.http.authorizeExchange();
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

		assertThat(result.getResponseCookies().getFirst("SESSION")).isNotNull();
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
		WebFilterChainFilter springSecurityFilterChain = WebFilterChainFilter.fromSecurityWebFilterChains(
			this.http.build());
		return WebTestClientBuilder.bindToWebFilters(springSecurityFilterChain).build();
	}
}
