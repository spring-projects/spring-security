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

package org.springframework.security.web.server.context;

import java.security.Principal;

import reactor.core.publisher.Mono;

import org.springframework.security.core.context.SecurityContext;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.ServerWebExchangeDecorator;

/**
 * Overrides the {@link ServerWebExchange#getPrincipal()} with the provided
 * SecurityContext
 *
 * @author Rob Winch
 * @since 5.0
 * @see SecurityContextServerWebExchangeWebFilter
 */
public class SecurityContextServerWebExchange extends ServerWebExchangeDecorator {

	private final Mono<SecurityContext> context;

	public SecurityContextServerWebExchange(ServerWebExchange delegate, Mono<SecurityContext> context) {
		super(delegate);
		this.context = context;
	}

	@Override
	@SuppressWarnings("unchecked")
	public <T extends Principal> Mono<T> getPrincipal() {
		return this.context.map(c -> (T) c.getAuthentication());
	}

}
