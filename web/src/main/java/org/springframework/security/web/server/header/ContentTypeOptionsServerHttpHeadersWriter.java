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

package org.springframework.security.web.server.header;

import reactor.core.publisher.Mono;

import org.springframework.web.server.ServerWebExchange;

/**
 * Adds X-Content-Type-Options: nosniff
 *
 * @author Rob Winch
 * @since 5.0
 */
public class ContentTypeOptionsServerHttpHeadersWriter implements ServerHttpHeadersWriter {

	public static final String X_CONTENT_OPTIONS = "X-Content-Type-Options";

	public static final String NOSNIFF = "nosniff";

	/**
	 * The delegate to write all the cache control related headers
	 */
	private static final ServerHttpHeadersWriter CONTENT_TYPE_HEADERS = StaticServerHttpHeadersWriter.builder()
			.header(X_CONTENT_OPTIONS, NOSNIFF).build();

	@Override
	public Mono<Void> writeHttpHeaders(ServerWebExchange exchange) {
		return CONTENT_TYPE_HEADERS.writeHttpHeaders(exchange);
	}

}
