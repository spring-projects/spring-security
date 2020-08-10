/*
 * Copyright 2002-2019 the original author or authors.
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
package org.springframework.security.web.server.authentication.logout;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.header.ServerHttpHeadersWriter;
import org.springframework.util.Assert;

import reactor.core.publisher.Mono;

/**
 * <p>
 * A {@link ServerLogoutHandler} implementation which writes HTTP headers during logout.
 * </p>
 *
 * @author MD Sayem Ahmed
 * @since 5.2
 */
public final class HeaderWriterServerLogoutHandler implements ServerLogoutHandler {

	private final ServerHttpHeadersWriter headersWriter;

	/**
	 * <p>
	 * Constructs a new instance using the {@link ServerHttpHeadersWriter} implementation.
	 * </p>
	 * @param headersWriter a {@link ServerHttpHeadersWriter} implementation
	 * @throws IllegalArgumentException if the argument is null
	 */
	public HeaderWriterServerLogoutHandler(ServerHttpHeadersWriter headersWriter) {
		Assert.notNull(headersWriter, "headersWriter cannot be null");
		this.headersWriter = headersWriter;
	}

	@Override
	public Mono<Void> logout(WebFilterExchange exchange, Authentication authentication) {
		return this.headersWriter.writeHttpHeaders(exchange.getExchange());
	}

}
