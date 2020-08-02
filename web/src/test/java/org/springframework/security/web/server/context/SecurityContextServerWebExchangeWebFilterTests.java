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

package org.springframework.security.web.server.context;

import org.junit.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.handler.DefaultWebFilterChain;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Rob Winch
 * @since 5.0
 */
public class SecurityContextServerWebExchangeWebFilterTests {

	SecurityContextServerWebExchangeWebFilter filter = new SecurityContextServerWebExchangeWebFilter();

	Authentication principal = new TestingAuthenticationToken("user", "password", "ROLE_USER");

	ServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/").build());

	@Test
	public void filterWhenExistingContextAndPrincipalNotNullThenContextPopulated() {
		Mono<Void> result = this.filter
				.filter(this.exchange, new DefaultWebFilterChain((e) -> e.getPrincipal()
						.doOnSuccess((contextPrincipal) -> assertThat(contextPrincipal).isEqualTo(this.principal))
						.flatMap((contextPrincipal) -> Mono.subscriberContext())
						.doOnSuccess((context) -> assertThat(context.<String>get("foo")).isEqualTo("bar")).then()))
				.subscriberContext((context) -> context.put("foo", "bar"))
				.subscriberContext(ReactiveSecurityContextHolder.withAuthentication(this.principal));
		StepVerifier.create(result).verifyComplete();
	}

	@Test
	public void filterWhenPrincipalNotNullThenContextPopulated() {
		Mono<Void> result = this.filter
				.filter(this.exchange,
						new DefaultWebFilterChain((e) -> e.getPrincipal()
								.doOnSuccess(
										(contextPrincipal) -> assertThat(contextPrincipal).isEqualTo(this.principal))
								.then()))
				.subscriberContext(ReactiveSecurityContextHolder.withAuthentication(this.principal));
		StepVerifier.create(result).verifyComplete();
	}

	@Test
	public void filterWhenPrincipalNullThenContextEmpty() {
		Authentication defaultAuthentication = new TestingAuthenticationToken("anonymouse", "anonymous", "TEST");
		Mono<Void> result = this.filter.filter(this.exchange,
				new DefaultWebFilterChain((e) -> e.getPrincipal().defaultIfEmpty(defaultAuthentication)
						.doOnSuccess(
								(contextPrincipal) -> assertThat(contextPrincipal).isEqualTo(defaultAuthentication))
						.then()));
		StepVerifier.create(result).verifyComplete();
	}

}
