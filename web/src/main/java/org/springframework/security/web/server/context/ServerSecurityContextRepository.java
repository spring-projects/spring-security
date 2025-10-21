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
 * Strategy used for persisting a {@link SecurityContext} between requests.
 *
 * @author Rob Winch
 * @since 5.0
 * @see ReactorContextWebFilter
 */
public interface ServerSecurityContextRepository {

	/**
	 * Saves the SecurityContext
	 * @param exchange the exchange to associate to the SecurityContext
	 * @param context the SecurityContext to save
	 * @return a completion notification (success or error)
	 */
	Mono<Void> save(ServerWebExchange exchange, @Nullable SecurityContext context);

	/**
	 * Loads the SecurityContext associated with the {@link ServerWebExchange}
	 * @param exchange the exchange to look up the {@link SecurityContext}
	 * @return the {@link SecurityContext} to lookup or empty if not found. Never null
	 */
	Mono<SecurityContext> load(ServerWebExchange exchange);

}
