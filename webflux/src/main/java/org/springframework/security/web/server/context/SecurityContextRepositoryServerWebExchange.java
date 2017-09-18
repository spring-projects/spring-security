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
package org.springframework.security.web.server.context;

import java.security.Principal;

import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.ServerWebExchangeDecorator;

import reactor.core.publisher.Mono;

/**
 * @author Rob Winch
 * @since 5.0
 */
public class SecurityContextRepositoryServerWebExchange extends ServerWebExchangeDecorator {
	private final SecurityContextRepository repository;

	public SecurityContextRepositoryServerWebExchange(ServerWebExchange delegate, SecurityContextRepository repository) {
		super(delegate);
		this.repository = repository;
	}

	@Override
	@SuppressWarnings("unchecked")
	public <T extends Principal> Mono<T> getPrincipal() {
		return Mono.defer(() ->
			this.repository.load(this)
				.filter(c -> c.getAuthentication() != null)
				.flatMap(c -> Mono.just((T) c.getAuthentication()))
				.switchIfEmpty( super.getPrincipal() )
		);
	}
}
