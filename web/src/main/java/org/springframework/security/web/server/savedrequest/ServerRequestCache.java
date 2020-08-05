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

import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.URI;

/**
 * Saves a {@link ServerHttpRequest} so it can be "replayed" later. This is useful for
 * when a page was requested and authentication is necessary.
 *
 * @author Rob Winch
 * @since 5.0
 */
public interface ServerRequestCache {

	/**
	 * Save the {@link ServerHttpRequest}
	 * @param exchange the exchange to save
	 * @return Return a {@code Mono<Void>} which only replays complete and error signals
	 * from this {@link Mono}.
	 */
	Mono<Void> saveRequest(ServerWebExchange exchange);

	/**
	 * Get the URI that can be redirected to trigger the saved request to be used
	 * @param exchange the exchange to obtain the saved {@link ServerHttpRequest} from
	 * @return the URI that can be redirected to trigger the saved request to be used
	 */
	Mono<URI> getRedirectUri(ServerWebExchange exchange);

	/**
	 * If the provided {@link ServerWebExchange} matches the saved
	 * {@link ServerHttpRequest} gets the saved {@link ServerHttpRequest}
	 * @param exchange the exchange to obtain the request from
	 * @return the {@link ServerHttpRequest}
	 */
	Mono<ServerHttpRequest> removeMatchingRequest(ServerWebExchange exchange);

}
