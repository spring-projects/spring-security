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

package org.springframework.security.web.server.authentication;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.DefaultServerRedirectStrategy;
import org.springframework.security.web.server.ServerRedirectStrategy;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.savedrequest.ServerRequestCache;
import org.springframework.security.web.server.savedrequest.WebSessionServerRequestCache;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.URI;

/**
 * Performs a redirect on authentication success. The default is to redirect to a saved request if present and
 * otherwise "/".
 * @author Rob Winch
 * @since 5.0
 */
public class RedirectServerAuthenticationSuccessHandler
	implements ServerAuthenticationSuccessHandler {
	private URI location = URI.create("/");

	private ServerRedirectStrategy redirectStrategy = new DefaultServerRedirectStrategy();

	private ServerRequestCache requestCache = new WebSessionServerRequestCache();

	/**
	 * Creates a new instance with location of "/"
	 */
	public RedirectServerAuthenticationSuccessHandler() {}

	/**
	 * Creates a new instance with the specified location
	 * @param location the location to redirect if the no request is cached in
	 * {@link #setRequestCache(ServerRequestCache)}
	 */
	public RedirectServerAuthenticationSuccessHandler(String location) {
		this.location = URI.create(location);
	}

	/**
	 * Sets the {@link ServerRequestCache} used to redirect to. Default is {@link WebSessionServerRequestCache}.
	 * @param requestCache the cache to use
	 */
	public void setRequestCache(ServerRequestCache requestCache) {
		Assert.notNull(requestCache, "requestCache cannot be null");
		this.requestCache = requestCache;
	}

	@Override
	public Mono<Void> onAuthenticationSuccess(WebFilterExchange webFilterExchange,
		Authentication authentication) {
		ServerWebExchange exchange = webFilterExchange.getExchange();
		return this.requestCache.getRedirectUri(exchange)
			.defaultIfEmpty(this.location)
			.flatMap(location -> this.redirectStrategy.sendRedirect(exchange, location));
	}

	/**
	 * Where the user is redirected to upon authentication success
	 * @param location the location to redirect to. The default is "/"
	 */
	public void setLocation(URI location) {
		Assert.notNull(location, "location cannot be null");
		this.location = location;
	}

	/**
	 * The RedirectStrategy to use.
	 * @param redirectStrategy the strategy to use. Default is DefaultRedirectStrategy.
	 */
	public void setRedirectStrategy(ServerRedirectStrategy redirectStrategy) {
		Assert.notNull(redirectStrategy, "redirectStrategy cannot be null");
		this.redirectStrategy = redirectStrategy;
	}
}
