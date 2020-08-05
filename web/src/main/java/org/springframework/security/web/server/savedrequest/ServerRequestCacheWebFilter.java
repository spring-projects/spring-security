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

import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

/**
 * A {@link WebFilter} that replays any matching request in {@link ServerRequestCache}
 *
 * @author Rob Winch
 * @since 5.0
 */
public class ServerRequestCacheWebFilter implements WebFilter {

	private ServerRequestCache requestCache = new WebSessionServerRequestCache();

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
		return this.requestCache.removeMatchingRequest(exchange).map(r -> exchange.mutate().request(r).build())
				.defaultIfEmpty(exchange).flatMap(e -> chain.filter(e));
	}

	public void setRequestCache(ServerRequestCache requestCache) {
		Assert.notNull(requestCache, "requestCache cannot be null");
		this.requestCache = requestCache;
	}

}
