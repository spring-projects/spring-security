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

package org.springframework.security.web.server.context;

import org.junit.Test;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.handler.DefaultWebFilterChain;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import reactor.util.context.Context;

import java.security.Principal;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Rob Winch
 * @since 5.0
 */
public class AuthenticationReactorContextFilterTests {
	AuthenticationReactorContextFilter filter = new AuthenticationReactorContextFilter();

	Principal principal = new TestingAuthenticationToken("user","password", "ROLE_USER");

	ServerWebExchange exchange = MockServerHttpRequest.get("/").toExchange();

	@Test
	public void filterWhenExistingContextAndPrincipalNotNullThenContextPopulated() {
		exchange = exchange.mutate().principal(Mono.just(principal)).build();
		StepVerifier.create(filter.filter(exchange,
			new DefaultWebFilterChain( e ->
				Mono.subscriberContext().doOnSuccess( context -> {
					Principal contextPrincipal = context.<Mono<Principal>>get(Authentication.class).block();
					assertThat(contextPrincipal).isEqualTo(principal);
					assertThat(context.<String>get("foo")).isEqualTo("bar");
				})
				.then()
			)
		)
		.subscriberContext( context -> context.put("foo", "bar")))
		.verifyComplete();
	}

	@Test
	public void filterWhenPrincipalNotNullThenContextPopulated() {
		exchange = exchange.mutate().principal(Mono.just(principal)).build();
		StepVerifier.create(filter.filter(exchange,
			new DefaultWebFilterChain( e ->
				Mono.subscriberContext().doOnSuccess( context -> {
					Principal contextPrincipal = context.<Mono<Principal>>get(Authentication.class).block();
					assertThat(contextPrincipal).isEqualTo(principal);
				})
				.then()
			)
		))
		.verifyComplete();
	}

	@Test
	public void filterWhenPrincipalNullThenContextEmpty() {
		Context defaultContext = Context.empty();
		StepVerifier.create(filter.filter(exchange,
			new DefaultWebFilterChain( e ->
				Mono.subscriberContext()
					.defaultIfEmpty(defaultContext)
					.doOnSuccess( context -> {
					Principal contextPrincipal = context.<Mono<Principal>>get(Authentication.class).block();
					assertThat(contextPrincipal).isNull();
				})
				.then()
			)
		))
		.verifyComplete();
	}
}
