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

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.test.web.reactive.server.WebTestHandler;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.security.Principal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;


/**
 * @author Rob Winch
 * @since 5.0
 */
@RunWith(MockitoJUnitRunner.class)
public class SecurityContextRepositoryWebFilterTests {
	@Mock
	Authentication principal;

	@Mock
	SecurityContextRepository repository;

	MockServerHttpRequest.BaseBuilder<?> exchange = MockServerHttpRequest.get("/");

	SecurityContextRepositoryWebFilter filter;

	WebTestHandler filters;


	@Before
	public void setup() {
		filter = new SecurityContextRepositoryWebFilter(repository);
		filters = WebTestHandler.bindToWebFilters(filter);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorNullSecurityContextRepository() {
		SecurityContextRepository repository = null;
		new SecurityContextRepositoryWebFilter(repository);
	}

	@Test
	public void filterWhenNoPrincipalAccessThenNoInteractions() {
		filters.exchange(exchange);

		verifyZeroInteractions(repository);
	}

	@Test
	public void filterWhenGetPrincipalMonoThenNoInteractions() {
		filters = WebTestHandler.bindToWebFilters(filter, (e,c) -> {
			Mono<Principal> p = e.getPrincipal();
			return c.filter(e);
		});

		filters.exchange(exchange);

		verifyZeroInteractions(repository);
	}

	// We must use the original principal if the result is empty for test support to work
	@Test
	public void filterWhenEmptyAndGetPrincipalThenInteractAndUseOriginalPrincipal() {
		when(repository.load(any())).thenReturn(Mono.empty());
		filters = WebTestHandler.bindToWebFilters(filter, (e,c) -> e.getPrincipal().flatMap( p-> c.filter(e))) ;

		ServerWebExchange exchangeWithPrincipal = this.exchange.toExchange().mutate().principal(Mono.just(principal)).build();
		WebTestHandler.WebHandlerResult result = filters.exchange(exchangeWithPrincipal);

		verify(repository).load(any());
		assertThat(result.getExchange().getPrincipal().block()).isSameAs(principal);
	}

	@Test
	public void filterWhenPrincipalAndGetPrincipalThenInteractAndUseOriginalPrincipal() {
		SecurityContextImpl context = new SecurityContextImpl();
		context.setAuthentication(principal);
		when(repository.load(any())).thenReturn(Mono.just(context));
		filters = WebTestHandler.bindToWebFilters(filter, (e,c) -> e.getPrincipal().flatMap( p-> c.filter(e))) ;

		WebTestHandler.WebHandlerResult result = filters.exchange(exchange);

		verify(repository).load(any());
		assertThat(result.getExchange().getPrincipal().block()).isSameAs(principal);
	}
}
