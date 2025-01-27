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

package org.springframework.security.web.server.firewall;

import reactor.core.publisher.Mono;

import org.springframework.web.server.ServerWebExchange;

/**
 * Handles {@link ServerExchangeRejectedException} thrown by
 * {@link ServerWebExchangeFirewall}.
 *
 * @author Rob Winch
 * @since 5.7.13
 */
public interface ServerExchangeRejectedHandler {

	/**
	 * Handles an request rejected failure.
	 * @param exchange the {@link ServerWebExchange} that was rejected
	 * @param serverExchangeRejectedException that caused the invocation
	 */
	Mono<Void> handle(ServerWebExchange exchange, ServerExchangeRejectedException serverExchangeRejectedException);

}
