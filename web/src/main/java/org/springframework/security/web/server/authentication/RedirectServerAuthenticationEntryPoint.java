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

import java.net.URI;

import org.springframework.security.web.server.DefaultServerRedirectStrategy;
import org.springframework.security.web.server.ServerRedirectStrategy;
import org.springframework.security.web.server.savedrequest.ServerRequestCache;
import org.springframework.security.web.server.savedrequest.WebSessionServerRequestCache;
import reactor.core.publisher.Mono;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;

/**
 * Performs a redirect to a specified location.
 *
 * @author Rob Winch
 * @since 5.0
 */
public class RedirectServerAuthenticationEntryPoint
	implements ServerAuthenticationEntryPoint {
	private final URI location;

	private ServerRedirectStrategy redirectStrategy = new DefaultServerRedirectStrategy();

	private ServerRequestCache requestCache = new WebSessionServerRequestCache();

	/**
	 * Creates an instance
	 * @param location the location to redirect to (i.e. "/logout-success")
	 */
	public RedirectServerAuthenticationEntryPoint(String location) {
		Assert.notNull(location, "location cannot be null");
		this.location = URI.create(location);
	}

	/**
	 * The request cache to use to save the request before sending a redirect.
	 * @param requestCache the cache to redirect to.
	 */
	public void setRequestCache(ServerRequestCache requestCache) {
		Assert.notNull(requestCache, "requestCache cannot be null");
		this.requestCache = requestCache;
	}

	@Override
	public Mono<Void> commence(ServerWebExchange exchange, AuthenticationException e) {
		return this.requestCache.saveRequest(exchange)
			.then(this.redirectStrategy.sendRedirect(exchange, this.location));
	}

	/**
	 * Sets the RedirectStrategy to use.
	 * @param redirectStrategy the strategy to use. Default is DefaultRedirectStrategy.
	 */
	public void setRedirectStrategy(ServerRedirectStrategy redirectStrategy) {
		Assert.notNull(redirectStrategy, "redirectStrategy cannot be null");
		this.redirectStrategy = redirectStrategy;
	}
}
