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

import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.DefaultRedirectStrategy;
import org.springframework.security.web.server.RedirectStrategy;
import org.springframework.security.web.server.context.SecurityContextRepository;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.context.WebSessionSecurityContextRepository;
import reactor.core.publisher.Mono;

import java.net.URI;

/**
 * @author Rob Winch
 * @since 5.0
 */
public class SecurityContextRepositoryLogoutHandler implements LogoutHandler {
	private SecurityContextRepository repository = new WebSessionSecurityContextRepository();

	private URI logoutSuccessUrl = URI.create("/login?logout");

	private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

	@Override
	public Mono<Void> logout(WebFilterExchange exchange,
		Authentication authentication) {
		return this.repository.save(exchange.getExchange(), null)
			.then(this.redirectStrategy.sendRedirect(exchange.getExchange(), this.logoutSuccessUrl));
	}
}
