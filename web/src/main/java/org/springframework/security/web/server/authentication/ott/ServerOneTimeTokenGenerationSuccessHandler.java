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

package org.springframework.security.web.server.authentication.ott;

import reactor.core.publisher.Mono;

import org.springframework.security.authentication.ott.OneTimeToken;
import org.springframework.web.server.ServerWebExchange;

/**
 * Defines a reactive strategy to handle generated one-time tokens.
 *
 * @author Max Batischev
 * @since 6.4
 */
@FunctionalInterface
public interface ServerOneTimeTokenGenerationSuccessHandler {

	/**
	 * Handles generated one-time tokens
	 * @param exchange the {@link ServerWebExchange} to use
	 * @param oneTimeToken the {@link OneTimeToken} to handle
	 * @return a completion handling (success or error)
	 */
	Mono<Void> handle(ServerWebExchange exchange, OneTimeToken oneTimeToken);

}
