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

import org.springframework.security.web.server.firewall.HttpStatusExchangeRejectedHandler;
import org.springframework.security.web.server.firewall.ServerExchangeRejectedException;
import org.springframework.security.web.server.firewall.ServerExchangeRejectedHandler;
import org.springframework.security.web.server.firewall.ServerWebExchangeFirewall;
import org.springframework.security.web.server.firewall.StrictServerWebExchangeFirewall;
import org.springframework.util.Assert;
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

	private ServerWebExchangeFirewall firewall = new StrictServerWebExchangeFirewall();

	private ServerExchangeRejectedHandler exchangeRejectedHandler = new HttpStatusExchangeRejectedHandler();

	public WebFilterChainProxy(List<SecurityWebFilterChain> filters) {
		this.filters = filters;
	}

	public WebFilterChainProxy(SecurityWebFilterChain... filters) {
		this.filters = Arrays.asList(filters);
	}

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
		return this.firewall.getFirewalledExchange(exchange)
				.flatMap((firewalledExchange) -> filterFirewalledExchange(firewalledExchange, chain))
				.onErrorResume(ServerExchangeRejectedException.class,
						(rejected) -> this.exchangeRejectedHandler.handle(exchange, rejected).then(Mono.empty()));
	}

	private Mono<Void> filterFirewalledExchange(ServerWebExchange firewalledExchange, WebFilterChain chain) {
		return Flux.fromIterable(this.filters)
				.filterWhen((securityWebFilterChain) -> securityWebFilterChain.matches(firewalledExchange)).next()
				.switchIfEmpty(chain.filter(firewalledExchange).then(Mono.empty()))
				.flatMap((securityWebFilterChain) -> securityWebFilterChain.getWebFilters().collectList())
				.map((filters) -> new FilteringWebHandler(chain::filter, filters)).map(DefaultWebFilterChain::new)
				.flatMap((securedChain) -> securedChain.filter(firewalledExchange));
	}

	/**
	 * Protects the application using the provided
	 * {@link StrictServerWebExchangeFirewall}.
	 * @param firewall the {@link StrictServerWebExchangeFirewall} to use. Cannot be null.
	 * @since 5.7.13
	 */
	public void setFirewall(ServerWebExchangeFirewall firewall) {
		Assert.notNull(firewall, "firewall cannot be null");
		this.firewall = firewall;
	}

	/**
	 * Handles {@link ServerExchangeRejectedException} when the
	 * {@link ServerWebExchangeFirewall} rejects the provided {@link ServerWebExchange}.
	 * @param exchangeRejectedHandler the {@link ServerExchangeRejectedHandler} to use.
	 * @since 5.7.13
	 */
	public void setExchangeRejectedHandler(ServerExchangeRejectedHandler exchangeRejectedHandler) {
		Assert.notNull(exchangeRejectedHandler, "exchangeRejectedHandler cannot be null");
		this.exchangeRejectedHandler = exchangeRejectedHandler;
	}

}
