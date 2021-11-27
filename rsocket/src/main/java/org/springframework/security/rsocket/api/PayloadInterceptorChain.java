/*
 * Copyright 2019 the original author or authors.
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

package org.springframework.security.rsocket.api;

import reactor.core.publisher.Mono;

/**
 * Contract to allow a {@link PayloadInterceptor} to delegate to the next in the chain. *
 *
 * @author Rob Winch
 * @since 5.2
 */
public interface PayloadInterceptorChain {

	/**
	 * Process the payload exchange.
	 * @param exchange the current server exchange
	 * @return {@code Mono<Void>} to indicate when request processing is complete
	 */
	Mono<Void> next(PayloadExchange exchange);

}
