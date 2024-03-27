/*
 * Copyright 2002-2024 the original author or authors.
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

import java.util.ArrayList;
import java.util.List;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.util.Assert;

/**
 * A {@link ServerLogoutSuccessHandler}, that iterates over multiple
 * {@link ServerLogoutSuccessHandler}.
 *
 * @author Max Batischev
 * @since 6.3
 */
public final class DelegatingServerLogoutSuccessHandler implements ServerLogoutSuccessHandler {

	private final List<ServerLogoutSuccessHandler> delegates;

	public DelegatingServerLogoutSuccessHandler(List<ServerLogoutSuccessHandler> delegates) {
		Assert.notEmpty(delegates, "delegates cannot be null");
		this.delegates = new ArrayList<>(delegates);
	}

	public DelegatingServerLogoutSuccessHandler(ServerLogoutSuccessHandler... delegates) {
		Assert.notEmpty(delegates, "delegates cannot be null");
		this.delegates = List.of(delegates);
	}

	@Override
	public Mono<Void> onLogoutSuccess(WebFilterExchange exchange, Authentication authentication) {
		return Flux.fromIterable(this.delegates)
			.concatMap((delegate) -> delegate.onLogoutSuccess(exchange, authentication))
			.then();
	}

}
