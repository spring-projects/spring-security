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

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.DefaultServerRedirectStrategy;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.security.web.server.ServerRedirectStrategy;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.savedrequest.ServerRequestCache;
import org.springframework.security.web.server.savedrequest.WebSessionServerRequestCache;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.URI;

/**
 * Performs a redirect to a specified location.
 *
 * @author Rob Winch
 * @since 5.0
 */
public class RedirectServerAuthenticationFailureHandler
	implements ServerAuthenticationFailureHandler {
	private final URI location;

	private ServerRedirectStrategy serverRedirectStrategy = new DefaultServerRedirectStrategy();

	public RedirectServerAuthenticationFailureHandler(String location) {
		Assert.notNull(location, "location cannot be null");
		this.location = URI.create(location);
	}

	/**
	 * Sets the RedirectStrategy to use.
	 * @param serverRedirectStrategy the strategy to use. Default is DefaultRedirectStrategy.
	 */
	public void setServerRedirectStrategy(ServerRedirectStrategy serverRedirectStrategy) {
		Assert.notNull(serverRedirectStrategy, "redirectStrategy cannot be null");
		this.serverRedirectStrategy = serverRedirectStrategy;
	}

	@Override
	public Mono<Void> onAuthenticationFailure(
		WebFilterExchange webFilterExchange, AuthenticationException exception) {
		return this.serverRedirectStrategy.sendRedirect(webFilterExchange.getExchange(), this.location);
	}
}
