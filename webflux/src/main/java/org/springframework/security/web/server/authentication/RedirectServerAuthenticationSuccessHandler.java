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

package org.springframework.security.web.server.authentication;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.DefaultServerRedirectStrategy;
import org.springframework.security.web.server.ServerRedirectStrategy;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.URI;

/**
 * @author Rob Winch
 * @since 5.0
 */
public class RedirectServerAuthenticationSuccessHandler
	implements ServerAuthenticationSuccessHandler {
	private URI location = URI.create("/");

	private ServerRedirectStrategy serverRedirectStrategy = new DefaultServerRedirectStrategy();

	public RedirectServerAuthenticationSuccessHandler() {}

	public RedirectServerAuthenticationSuccessHandler(String location) {
		this.location = URI.create(location);
	}

	@Override
	public Mono<Void> success(Authentication authentication, WebFilterExchange webFilterExchange) {
		ServerWebExchange exchange = webFilterExchange.getExchange();
		return this.serverRedirectStrategy.sendRedirect(exchange, this.location);
	}

	/**
	 * Where the user is redirected to upon AuthenticationSuccess
	 * @param location the location to redirect to. The default is "/"
	 */
	public void setLocation(URI location) {
		Assert.notNull(location, "location cannot be null");
		this.location = location;
	}

	/**
	 * The RedirectStrategy to use.
	 * @param serverRedirectStrategy the strategy to use. Default is DefaultRedirectStrategy.
	 */
	public void setServerRedirectStrategy(ServerRedirectStrategy serverRedirectStrategy) {
		Assert.notNull(serverRedirectStrategy, "redirectStrategy cannot be null");
		this.serverRedirectStrategy = serverRedirectStrategy;
	}
}
