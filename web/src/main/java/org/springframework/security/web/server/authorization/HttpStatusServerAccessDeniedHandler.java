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

package org.springframework.security.web.server.authorization;

import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.MediaType;
import reactor.core.publisher.Mono;

import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;

import java.nio.charset.Charset;

/**
 * Sets the provided HTTP Status when access is denied.
 *
 * @author Rob Winch
 * @since 5.0
 */
public class HttpStatusServerAccessDeniedHandler implements ServerAccessDeniedHandler {

	private final HttpStatus httpStatus;

	/**
	 * Creates an instance with the provided status
	 * @param httpStatus the status to use
	 */
	public HttpStatusServerAccessDeniedHandler(HttpStatus httpStatus) {
		Assert.notNull(httpStatus, "httpStatus cannot be null");
		this.httpStatus = httpStatus;
	}

	@Override
	public Mono<Void> handle(ServerWebExchange exchange, AccessDeniedException e) {
		return Mono.defer(() -> Mono.just(exchange.getResponse())).flatMap(response -> {
			response.setStatusCode(this.httpStatus);
			response.getHeaders().setContentType(MediaType.TEXT_PLAIN);
			DataBufferFactory dataBufferFactory = response.bufferFactory();
			DataBuffer buffer = dataBufferFactory.wrap(e.getMessage().getBytes(Charset.defaultCharset()));
			return response.writeWith(Mono.just(buffer)).doOnError(error -> DataBufferUtils.release(buffer));
		});
	}

}
