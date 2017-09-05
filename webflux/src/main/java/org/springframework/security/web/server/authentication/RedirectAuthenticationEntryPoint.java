/*
 *
 *  * Copyright 2002-2017 the original author or authors.
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *      http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package org.springframework.security.web.server.authentication;

import java.net.URI;

import org.springframework.security.web.server.DefaultRedirectStrategy;
import org.springframework.security.web.server.RedirectStrategy;
import reactor.core.publisher.Mono;

import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.AuthenticationEntryPoint;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;

/**
 * Performs a redirect to a specified location.
 *
 * @author Rob Winch
 * @since 5.0
 */
public class RedirectAuthenticationEntryPoint implements AuthenticationEntryPoint {
	private final URI location;

	private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

	public RedirectAuthenticationEntryPoint(String location) {
		Assert.notNull(location, "location cannot be null");
		this.location = URI.create(location);
	}

	@Override
	public Mono<Void> commence(ServerWebExchange exchange, AuthenticationException e) {
		return this.redirectStrategy.sendRedirect(exchange, this.location);
	}

	/**
	 * Sets the RedirectStrategy to use.
	 * @param redirectStrategy the strategy to use. Default is DefaultRedirectStrategy.
	 */
	public void setRedirectStrategy(RedirectStrategy redirectStrategy) {
		Assert.notNull(redirectStrategy, "redirectStrategy cannot be null");
		this.redirectStrategy = redirectStrategy;
	}
}
