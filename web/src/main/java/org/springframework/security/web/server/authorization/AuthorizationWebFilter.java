/*
 * Copyright 2002-2020 the original author or authors.
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
package org.springframework.security.web.server.authorization;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

import reactor.core.publisher.Mono;

/**
 *
 * @author Rob Winch
 * @author Mathieu Ouellet
 * @since 5.0
 */
public class AuthorizationWebFilter implements WebFilter {
	private static final Log logger = LogFactory.getLog(AuthorizationWebFilter.class);
	private ReactiveAuthorizationManager<? super ServerWebExchange> authorizationManager;

	public AuthorizationWebFilter(ReactiveAuthorizationManager<? super ServerWebExchange> authorizationManager) {
		this.authorizationManager = authorizationManager;
	}

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
		return ReactiveSecurityContextHolder.getContext()
			.filter(c -> c.getAuthentication() != null)
			.map(SecurityContext::getAuthentication)
			.as(authentication -> this.authorizationManager.verify(authentication, exchange))
			.doOnSuccess(it -> {
				if (logger.isDebugEnabled()) {
					logger.debug("Authorization successful");
				}
			})
			.doOnError(AccessDeniedException.class, e -> {
				if (logger.isDebugEnabled()) {
					logger.debug("Authorization failed: " + e.getMessage());
				}
			})
			.switchIfEmpty(chain.filter(exchange));
	}
}
