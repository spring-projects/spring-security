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

package org.springframework.security.web.server.authentication.logout;

import java.net.URI;

import reactor.core.publisher.Mono;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.DefaultServerRedirectStrategy;
import org.springframework.security.web.server.ServerRedirectStrategy;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.util.Assert;

/**
 * Performs a redirect on log out success.
 *
 * @author Rob Winch
 * @since 5.0
 */
public class RedirectServerLogoutSuccessHandler implements ServerLogoutSuccessHandler {

	public static final String DEFAULT_LOGOUT_SUCCESS_URL = "/login?logout";

	private URI logoutSuccessUrl = URI.create(DEFAULT_LOGOUT_SUCCESS_URL);

	private ServerRedirectStrategy redirectStrategy = new DefaultServerRedirectStrategy();

	@Override
	public Mono<Void> onLogoutSuccess(WebFilterExchange exchange, Authentication authentication) {
		return this.redirectStrategy.sendRedirect(exchange.getExchange(), this.logoutSuccessUrl);
	}

	/**
	 * The URL to redirect to after successfully logging out.
	 * @param logoutSuccessUrl the url to redirect to. Default is "/login?logout".
	 */
	public void setLogoutSuccessUrl(URI logoutSuccessUrl) {
		Assert.notNull(logoutSuccessUrl, "logoutSuccessUrl cannot be null");
		this.logoutSuccessUrl = logoutSuccessUrl;
	}

}
