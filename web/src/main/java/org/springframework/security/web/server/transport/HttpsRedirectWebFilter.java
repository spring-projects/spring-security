/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.web.server.transport;

import java.net.URI;
import java.util.Optional;

import reactor.core.publisher.Mono;

import org.springframework.security.web.PortMapper;
import org.springframework.security.web.PortMapperImpl;
import org.springframework.security.web.server.DefaultServerRedirectStrategy;
import org.springframework.security.web.server.ServerRedirectStrategy;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import org.springframework.web.util.UriComponentsBuilder;

import static org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers.anyExchange;

/**
 * Redirects any non-HTTPS request to its HTTPS equivalent.
 *
 * Can be configured to use a {@link ServerWebExchangeMatcher} to narrow which requests get redirected.
 *
 * Can also be configured for custom ports using {@link PortMapper}.
 *
 * @author Josh Cummings
 * @since 5.1
 */
public final class HttpsRedirectWebFilter implements WebFilter {
	private PortMapper portMapper = new PortMapperImpl();

	private ServerWebExchangeMatcher requiresHttpsRedirectMatcher = anyExchange();

	private final ServerRedirectStrategy redirectStrategy = new DefaultServerRedirectStrategy();

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
		return Mono.just(exchange)
				.filter(this::isInsecure)
				.flatMap(this.requiresHttpsRedirectMatcher::matches)
				.filter(matchResult -> matchResult.isMatch())
				.switchIfEmpty(chain.filter(exchange).then(Mono.empty()))
				.map(matchResult -> createRedirectUri(exchange))
				.flatMap(uri -> this.redirectStrategy.sendRedirect(exchange, uri));
	}

	/**
	 * Use this {@link PortMapper} for mapping custom ports
	 *
	 * @param portMapper the {@link PortMapper} to use
	 */
	public void setPortMapper(PortMapper portMapper) {
		Assert.notNull(portMapper, "portMapper cannot be null");
		this.portMapper = portMapper;
	}

	/**
	 * Use this {@link ServerWebExchangeMatcher} to narrow which requests are redirected to HTTPS.
	 *
	 * The filter already first checks for HTTPS in the uri scheme, so it is not necessary
	 * to include that check in this matcher.
	 *
	 * @param requiresHttpsRedirectMatcher the {@link ServerWebExchangeMatcher} to use
	 */
	public void setRequiresHttpsRedirectMatcher
			(ServerWebExchangeMatcher requiresHttpsRedirectMatcher) {

		Assert.notNull(requiresHttpsRedirectMatcher,
				"requiresHttpsRedirectMatcher cannot be null");
		this.requiresHttpsRedirectMatcher = requiresHttpsRedirectMatcher;
	}

	private boolean isInsecure(ServerWebExchange exchange) {
		return !"https".equals(exchange.getRequest().getURI().getScheme());
	}

	private URI createRedirectUri(ServerWebExchange exchange) {
		int port = exchange.getRequest().getURI().getPort();

		UriComponentsBuilder builder =
				UriComponentsBuilder.fromUri(exchange.getRequest().getURI());

		if (port > 0) {
			Optional.ofNullable(this.portMapper.lookupHttpsPort(port))
					.map(builder::port)
					.orElseThrow(() -> new IllegalStateException(
							"HTTP Port '" + port + "' does not have a corresponding HTTPS Port"));
		}

		return builder.scheme("https").build().toUri();
	}
}
