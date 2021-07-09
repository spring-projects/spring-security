/*
 * Copyright 2002-2020 the original author or authors.
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

package org.springframework.security.web.server.savedrequest;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilterChain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link ServerRequestCacheWebFilter}
 *
 * @author Eleftheria Stein
 */
@ExtendWith(MockitoExtension.class)
public class ServerRequestCacheWebFilterTests {

	private ServerRequestCacheWebFilter requestCacheFilter;

	@Mock
	private WebFilterChain chain;

	@Mock
	private ServerRequestCache requestCache;

	@Captor
	private ArgumentCaptor<ServerWebExchange> exchangeCaptor;

	@BeforeEach
	public void setup() {
		this.requestCacheFilter = new ServerRequestCacheWebFilter();
		this.requestCacheFilter.setRequestCache(this.requestCache);
		given(this.chain.filter(any(ServerWebExchange.class))).willReturn(Mono.empty());
	}

	@Test
	public void filterWhenRequestMatchesThenRequestUpdated() {
		ServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/"));
		ServerHttpRequest savedRequest = MockServerHttpRequest.get("/")
				.header(HttpHeaders.ACCEPT, MediaType.TEXT_HTML.getType()).build();
		given(this.requestCache.removeMatchingRequest(any())).willReturn(Mono.just(savedRequest));
		this.requestCacheFilter.filter(exchange, this.chain).block();
		verify(this.chain).filter(this.exchangeCaptor.capture());
		ServerWebExchange updatedExchange = this.exchangeCaptor.getValue();
		assertThat(updatedExchange.getRequest()).isEqualTo(savedRequest);
	}

	@Test
	public void filterWhenRequestDoesNotMatchThenRequestDoesNotChange() {
		MockServerHttpRequest initialRequest = MockServerHttpRequest.get("/").build();
		ServerWebExchange exchange = MockServerWebExchange.from(initialRequest);
		given(this.requestCache.removeMatchingRequest(any())).willReturn(Mono.empty());
		this.requestCacheFilter.filter(exchange, this.chain).block();
		verify(this.chain).filter(this.exchangeCaptor.capture());
		ServerWebExchange updatedExchange = this.exchangeCaptor.getValue();
		assertThat(updatedExchange.getRequest()).isEqualTo(initialRequest);
	}

}
