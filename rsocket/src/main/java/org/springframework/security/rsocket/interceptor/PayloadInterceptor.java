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

package org.springframework.security.rsocket.interceptor;

import reactor.core.publisher.Mono;

/**
 * Contract for interception-style, chained processing of Payloads that may
 * be used to implement cross-cutting, application-agnostic requirements such
 * as security, timeouts, and others.
 *
 * @author Rob Winch
 * @since 5.2
 */
public interface PayloadInterceptor {
	/**
	 * Process the Web request and (optionally) delegate to the next
	 * {@code PayloadInterceptor} through the given {@link PayloadInterceptorChain}.
	 * @param exchange the current payload exchange
	 * @param chain provides a way to delegate to the next interceptor
	 * @return {@code Mono<Void>} to indicate when payload processing is complete
	 */
	Mono<Void> intercept(PayloadExchange exchange, PayloadInterceptorChain chain);
}
