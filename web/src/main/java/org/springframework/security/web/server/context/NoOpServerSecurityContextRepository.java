/*
 * Copyright 2004-present the original author or authors.
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

import org.jspecify.annotations.Nullable;
import reactor.core.publisher.Mono;

import org.springframework.security.core.context.SecurityContext;
import org.springframework.web.server.ServerWebExchange;

/**
 * A do nothing implementation of {@link ServerSecurityContextRepository}. Used in
 * stateless applications.
 *
 * @author Rob Winch
 * @since 5.0
 */
public final class NoOpServerSecurityContextRepository implements ServerSecurityContextRepository {

	private static final NoOpServerSecurityContextRepository INSTANCE = new NoOpServerSecurityContextRepository();

	private NoOpServerSecurityContextRepository() {
	}

	@Override
	public Mono<Void> save(ServerWebExchange exchange, @Nullable SecurityContext context) {
		return Mono.empty();
	}

	@Override
	public Mono<SecurityContext> load(ServerWebExchange exchange) {
		return Mono.empty();
	}

	public static NoOpServerSecurityContextRepository getInstance() {
		return INSTANCE;
	}

}
