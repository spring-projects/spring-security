/*
 * Copyright 2002-2021 the original author or authors.
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

import java.net.URI;

import reactor.core.publisher.Mono;

import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher.MatchResult;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

/**
 * Web filter that redirects requests that match {@link ServerWebExchangeMatcher} to the
 * specified URL.
 *
 * @author Evgeniy Cheban
 * @since 5.6
 */
public final class ExchangeMatcherRedirectWebFilter implements WebFilter {

	private final ServerRedirectStrategy redirectStrategy = new DefaultServerRedirectStrategy();

	private final ServerWebExchangeMatcher exchangeMatcher;

	private final URI redirectUri;

	/**
	 * Create and initialize an instance of the web filter.
	 * @param exchangeMatcher the exchange matcher
	 * @param redirectUrl the redirect URL
	 */
	public ExchangeMatcherRedirectWebFilter(ServerWebExchangeMatcher exchangeMatcher, String redirectUrl) {
		Assert.notNull(exchangeMatcher, "exchangeMatcher cannot be null");
		Assert.hasText(redirectUrl, "redirectUrl cannot be empty");
		this.exchangeMatcher = exchangeMatcher;
		this.redirectUri = URI.create(redirectUrl);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
		// @formatter:off
		return this.exchangeMatcher.matches(exchange)
				.filter(MatchResult::isMatch)
				.switchIfEmpty(chain.filter(exchange).then(Mono.empty()))
				.flatMap((result) -> this.redirectStrategy.sendRedirect(exchange, this.redirectUri));
		// @formatter:on
	}

}
