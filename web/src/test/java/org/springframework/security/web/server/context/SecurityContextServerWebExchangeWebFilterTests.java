/*
 * Copyright 2002-2023 the original author or authors.
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

import java.util.Collections;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnJre;
import org.junit.jupiter.api.condition.JRE;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import reactor.test.StepVerifier;

import org.springframework.core.task.VirtualThreadTaskExecutor;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.test.web.reactive.server.WebTestHandler;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
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
			.filter(this.exchange,
					new DefaultWebFilterChain((e) -> e.getPrincipal()
						.doOnSuccess((contextPrincipal) -> assertThat(contextPrincipal).isEqualTo(this.principal))
						.flatMap((contextPrincipal) -> Mono.deferContextual(Mono::just))
						.doOnSuccess((context) -> assertThat(context.<String>get("foo")).isEqualTo("bar"))
						.then(), Collections.emptyList()))
			.contextWrite((context) -> context.put("foo", "bar"))
			.contextWrite(ReactiveSecurityContextHolder.withAuthentication(this.principal));
		StepVerifier.create(result).verifyComplete();
	}

	@Test
	public void filterWhenPrincipalNotNullThenContextPopulated() {
		Mono<Void> result = this.filter
			.filter(this.exchange,
					new DefaultWebFilterChain((e) -> e.getPrincipal()
						.doOnSuccess((contextPrincipal) -> assertThat(contextPrincipal).isEqualTo(this.principal))
						.then(), Collections.emptyList()))
			.contextWrite(ReactiveSecurityContextHolder.withAuthentication(this.principal));
		StepVerifier.create(result).verifyComplete();
	}

	@Test
	public void filterWhenPrincipalNullThenContextEmpty() {
		Authentication defaultAuthentication = new TestingAuthenticationToken("anonymouse", "anonymous", "TEST");
		Mono<Void> result = this.filter.filter(this.exchange,
				new DefaultWebFilterChain((e) -> e.getPrincipal()
					.defaultIfEmpty(defaultAuthentication)
					.doOnSuccess((contextPrincipal) -> assertThat(contextPrincipal).isEqualTo(defaultAuthentication))
					.then(), Collections.emptyList()));
		StepVerifier.create(result).verifyComplete();
	}

	@Test
	public void filterWhenThreadFactoryIsPlatformThenContextPopulated() {
		ThreadFactory threadFactory = Executors.defaultThreadFactory();
		assertPrincipalPopulated(threadFactory);
	}

	@Test
	@DisabledOnJre(JRE.JAVA_17)
	public void filterWhenThreadFactoryIsVirtualThenContextPopulated() {
		ThreadFactory threadFactory = new VirtualThreadTaskExecutor().getVirtualThreadFactory();
		assertPrincipalPopulated(threadFactory);
	}

	private void assertPrincipalPopulated(ThreadFactory threadFactory) {
		// @formatter:off
		WebFilter subscribeOnThreadFactory = (exchange, chain) -> chain.filter(exchange)
				.contextWrite(ReactiveSecurityContextHolder.withAuthentication(this.principal))
				.subscribeOn(Schedulers.newSingle(threadFactory));
		WebFilter assertPrincipal = (exchange, chain) -> exchange.getPrincipal()
				.doOnSuccess((principal) -> assertThat(principal).isSameAs(this.principal))
				.then(chain.filter(exchange));
		// @formatter:on
		WebTestHandler handler = WebTestHandler.bindToWebFilters(subscribeOnThreadFactory, this.filter,
				assertPrincipal);
		handler.exchange(this.exchange);
	}

}
