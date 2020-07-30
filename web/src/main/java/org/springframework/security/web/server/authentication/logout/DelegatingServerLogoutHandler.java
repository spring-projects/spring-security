/*
 * Copyright 2002-2018 the original author or authors.
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
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.util.Assert;

/**
 * Delegates to a collection of {@link ServerLogoutHandler} implementations.
 *
 * @author Eric Deandrea
 * @since 5.1
 */
public class DelegatingServerLogoutHandler implements ServerLogoutHandler {

	private final List<ServerLogoutHandler> delegates = new ArrayList<>();

	public DelegatingServerLogoutHandler(ServerLogoutHandler... delegates) {
		Assert.notEmpty(delegates, "delegates cannot be null or empty");
		this.delegates.addAll(Arrays.asList(delegates));
	}

	public DelegatingServerLogoutHandler(Collection<ServerLogoutHandler> delegates) {
		Assert.notEmpty(delegates, "delegates cannot be null or empty");
		this.delegates.addAll(delegates);
	}

	@Override
	public Mono<Void> logout(WebFilterExchange exchange, Authentication authentication) {
		return Flux.fromIterable(this.delegates).concatMap((delegate) -> delegate.logout(exchange, authentication))
				.then();
	}

}
