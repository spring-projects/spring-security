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

package org.springframework.security.web.server;

import java.util.Arrays;
import java.util.List;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import org.springframework.web.server.handler.DefaultWebFilterChain;
import org.springframework.web.server.handler.FilteringWebHandler;

/**
 * Used to delegate to a List of {@link SecurityWebFilterChain} instances.
 *
 * @author Rob Winch
 * @since 5.0
 */
public class WebFilterChainProxy implements WebFilter {

	private final List<SecurityWebFilterChain> filters;

	public WebFilterChainProxy(List<SecurityWebFilterChain> filters) {
		this.filters = filters;
	}

	public WebFilterChainProxy(SecurityWebFilterChain... filters) {
		this.filters = Arrays.asList(filters);
	}

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
		return Flux.fromIterable(this.filters)
				.filterWhen(securityWebFilterChain -> securityWebFilterChain.matches(exchange)).next()
				.switchIfEmpty(chain.filter(exchange).then(Mono.empty()))
				.flatMap(securityWebFilterChain -> securityWebFilterChain.getWebFilters().collectList())
				.map(filters -> new FilteringWebHandler(webHandler -> chain.filter(webHandler), filters))
				.map(handler -> new DefaultWebFilterChain(handler))
				.flatMap(securedChain -> securedChain.filter(exchange));
	}

}
