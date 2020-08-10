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

package org.springframework.security.web.server;

import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Defines a filter chain which is capable of being matched against a
 * {@link ServerWebExchange} in order to decide whether it applies to that request.
 *
 * @author Rob Winch
 * @since 5.0
 */
public interface SecurityWebFilterChain {

	/**
	 * Determines if this {@link SecurityWebFilterChain} matches the provided
	 * {@link ServerWebExchange}
	 * @param exchange the {@link ServerWebExchange}
	 * @return true if it matches, else false
	 */
	Mono<Boolean> matches(ServerWebExchange exchange);

	/**
	 * The {@link WebFilter} to use
	 * @return
	 */
	Flux<WebFilter> getWebFilters();

}
