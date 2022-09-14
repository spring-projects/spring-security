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

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import reactor.test.publisher.TestPublisher;
import reactor.util.context.Context;

import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.test.web.reactive.server.WebTestHandler;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import org.springframework.web.server.handler.DefaultWebFilterChain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;

/**
 * @author Rob Winch
 * @since 5.0
 */
@ExtendWith(MockitoExtension.class)
public class ReactorContextWebFilterTests {

	@Mock
	private Authentication principal;

	@Mock
	private ServerSecurityContextRepository repository;

	private MockServerHttpRequest.BaseBuilder<?> exchange = MockServerHttpRequest.get("/");

	private TestPublisher<SecurityContext> securityContext = TestPublisher.create();

	private ReactorContextWebFilter filter;

	private WebTestHandler handler;

	@BeforeEach
	public void setup() {
		this.filter = new ReactorContextWebFilter(this.repository);
		this.handler = WebTestHandler.bindToWebFilters(this.filter);
	}

	@Test
	public void constructorNullSecurityContextRepository() {
		assertThatIllegalArgumentException().isThrownBy(() -> new ReactorContextWebFilter(null));
	}

	@Test
	public void filterWhenNoPrincipalAccessThenNoInteractions() {
		given(this.repository.load(any())).willReturn(this.securityContext.mono());
		this.handler.exchange(this.exchange);
		this.securityContext.assertWasNotSubscribed();
	}

	@Test
	public void filterWhenGetPrincipalMonoThenNoInteractions() {
		given(this.repository.load(any())).willReturn(this.securityContext.mono());
		this.handler = WebTestHandler.bindToWebFilters(this.filter, (e, c) -> {
			ReactiveSecurityContextHolder.getContext();
			return c.filter(e);
		});
		this.handler.exchange(this.exchange);
		this.securityContext.assertWasNotSubscribed();
	}

	@Test
	public void filterWhenPrincipalAndGetPrincipalThenInteractAndUseOriginalPrincipal() {
		SecurityContextImpl context = new SecurityContextImpl(this.principal);
		given(this.repository.load(any())).willReturn(Mono.just(context));
		this.handler = WebTestHandler.bindToWebFilters(this.filter,
				(e, c) -> ReactiveSecurityContextHolder.getContext().map(SecurityContext::getAuthentication)
						.doOnSuccess((p) -> assertThat(p).isSameAs(this.principal)).flatMap((p) -> c.filter(e)));
		WebTestHandler.WebHandlerResult result = this.handler.exchange(this.exchange);
		this.securityContext.assertWasNotSubscribed();
	}

	@Test
	// gh-4962
	public void filterWhenMainContextThenDoesNotOverride() {
		given(this.repository.load(any())).willReturn(this.securityContext.mono());
		String contextKey = "main";
		WebFilter mainContextWebFilter = (e, c) -> c.filter(e).contextWrite(Context.of(contextKey, true));
		WebFilterChain chain = new DefaultWebFilterChain((e) -> Mono.empty(),
				List.of(mainContextWebFilter, this.filter));
		Mono<Void> filter = chain.filter(MockServerWebExchange.from(this.exchange.build()));
		StepVerifier.create(filter).expectAccessibleContext().hasKey(contextKey).then().verifyComplete();
	}

}
