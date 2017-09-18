/*
 *
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
 *
 */

package org.springframework.security.web.server.authentication.logout;

import reactor.core.publisher.Mono;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

/**
 * @author Rob Winch
 * @since 5.0
 */
public class LogoutWebFiter implements WebFilter {
	private AnonymousAuthenticationToken anonymousAuthenticationToken = new AnonymousAuthenticationToken("key", "anonymous",
		AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
	private LogoutHandler logoutHandler = new SecurityContextRepositoryLogoutHandler();

	private ServerWebExchangeMatcher requiresLogout = ServerWebExchangeMatchers
		.pathMatchers("/logout");

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
		return this.requiresLogout.matches(exchange)
			.filter( result -> result.isMatch())
			.switchIfEmpty(chain.filter(exchange).then(Mono.empty()))
			.flatMap( result -> authentication(exchange))
			.flatMap( authentication -> this.logoutHandler.logout(new WebFilterExchange(exchange, chain), authentication));
	}

	private Mono<Authentication> authentication(ServerWebExchange exchange) {
		return exchange.getPrincipal()
			.cast(Authentication.class)
			.defaultIfEmpty(this.anonymousAuthenticationToken);
	}
}
