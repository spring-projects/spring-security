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

package org.springframework.security.web.server.savedrequest;

import java.net.URI;

import reactor.core.publisher.Mono;

import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.server.ServerWebExchange;

/**
 * An implementation of {@link ServerRequestCache} that does nothing. This is used in
 * stateless applications
 *
 * @author Rob Winch
 * @since 5.0
 */
public class NoOpServerRequestCache implements ServerRequestCache {

	@Override
	public Mono<Void> saveRequest(ServerWebExchange exchange) {
		return Mono.empty();
	}

	@Override
	public Mono<URI> getRedirectUri(ServerWebExchange exchange) {
		return Mono.empty();
	}

	@Override
	public Mono<ServerHttpRequest> removeMatchingRequest(ServerWebExchange exchange) {
		return Mono.empty();
	}

	public static NoOpServerRequestCache getInstance() {
		return new NoOpServerRequestCache();
	}

	private NoOpServerRequestCache() {
	}

}
