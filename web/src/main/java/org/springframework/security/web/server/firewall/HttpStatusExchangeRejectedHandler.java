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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import reactor.core.publisher.Mono;

import org.springframework.core.log.LogMessage;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ServerWebExchange;

/**
 * A simple implementation of {@link ServerExchangeRejectedHandler} that sends an error
 * with configurable status code.
 *
 * @author Rob Winch
 * @since 6.4
 */
public class HttpStatusExchangeRejectedHandler implements ServerExchangeRejectedHandler {

	private static final Log logger = LogFactory.getLog(HttpStatusExchangeRejectedHandler.class);

	private final HttpStatus status;

	/**
	 * Constructs an instance which uses {@code 400} as response code.
	 */
	public HttpStatusExchangeRejectedHandler() {
		this(HttpStatus.BAD_REQUEST);
	}

	/**
	 * Constructs an instance which uses a configurable http code as response.
	 * @param status http status code to use
	 */
	public HttpStatusExchangeRejectedHandler(HttpStatus status) {
		this.status = status;
	}

	@Override
	public Mono<Void> handle(ServerWebExchange exchange,
			ServerExchangeRejectedException serverExchangeRejectedException) {
		return Mono.fromRunnable(() -> {
			logger.debug(
					LogMessage.format("Rejecting request due to: %s", serverExchangeRejectedException.getMessage()),
					serverExchangeRejectedException);
			exchange.getResponse().setStatusCode(this.status);
		});
	}

}
