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
 * Interface which can be used to reject potentially dangerous requests and/or wrap them
 * to control their behaviour.
 *
 * @author Rob Winch
 * @since 6.4
 */
public interface ServerWebExchangeFirewall {

	/**
	 * An implementation of {@link StrictServerWebExchangeFirewall} that does nothing.
	 * This is considered insecure and not recommended.
	 */
	ServerWebExchangeFirewall INSECURE_NOOP = (exchange) -> Mono.just(exchange);

	/**
	 * Get a {@link ServerWebExchange} that has firewall rules applied to it.
	 * @param exchange the {@link ServerWebExchange} to apply firewall rules to.
	 * @return the {@link ServerWebExchange} that has firewall rules applied to it.
	 * @throws ServerExchangeRejectedException when a rule is broken.
	 */
	Mono<ServerWebExchange> getFirewalledExchange(ServerWebExchange exchange);

}
