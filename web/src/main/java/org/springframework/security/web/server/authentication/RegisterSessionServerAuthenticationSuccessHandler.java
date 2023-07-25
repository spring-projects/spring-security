/*
 * Copyright 2002-2023 the original author or authors.
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

import reactor.core.publisher.Mono;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.session.ReactiveSessionInformation;
import org.springframework.security.core.session.ReactiveSessionRegistry;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.util.Assert;

/**
 * An implementation of {@link ServerAuthenticationSuccessHandler} that will register a
 * {@link ReactiveSessionInformation} with the provided {@link ReactiveSessionRegistry}.
 *
 * @author Marcus da Coregio
 * @since 6.3
 */
public final class RegisterSessionServerAuthenticationSuccessHandler implements ServerAuthenticationSuccessHandler {

	private final ReactiveSessionRegistry sessionRegistry;

	public RegisterSessionServerAuthenticationSuccessHandler(ReactiveSessionRegistry sessionRegistry) {
		Assert.notNull(sessionRegistry, "sessionRegistry cannot be null");
		this.sessionRegistry = sessionRegistry;
	}

	@Override
	public Mono<Void> onAuthenticationSuccess(WebFilterExchange exchange, Authentication authentication) {
		return exchange.getExchange()
			.getSession()
			.map((session) -> new ReactiveSessionInformation(authentication.getPrincipal(), session.getId(),
					session.getLastAccessTime()))
			.flatMap(this.sessionRegistry::saveSessionInformation);
	}

}
