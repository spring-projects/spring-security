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

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ServerWebExchange;

/**
 * Writes cache control related headers.
 *
 * <pre>
 * Cache-Control: no-cache, no-store, max-age=0, must-revalidate
 * Pragma: no-cache
 * Expires: 0
 * </pre>
 *
 * @author Rob Winch
 * @since 5.0
 */
public class CacheControlServerHttpHeadersWriter implements ServerHttpHeadersWriter {

	/**
	 * The value for expires value
	 */
	public static final String EXPIRES_VALUE = "0";

	/**
	 * The value for pragma value
	 */
	public static final String PRAGMA_VALUE = "no-cache";

	/**
	 * The value for cache control value
	 */
	public static final String CACHE_CONTRTOL_VALUE = "no-cache, no-store, max-age=0, must-revalidate";

	/**
	 * The delegate to write all the cache control related headers
	 */
	private static final ServerHttpHeadersWriter CACHE_HEADERS = StaticServerHttpHeadersWriter.builder()
			.header(HttpHeaders.CACHE_CONTROL, CacheControlServerHttpHeadersWriter.CACHE_CONTRTOL_VALUE)
			.header(HttpHeaders.PRAGMA, CacheControlServerHttpHeadersWriter.PRAGMA_VALUE)
			.header(HttpHeaders.EXPIRES, CacheControlServerHttpHeadersWriter.EXPIRES_VALUE).build();

	@Override
	public Mono<Void> writeHttpHeaders(ServerWebExchange exchange) {
		if (exchange.getResponse().getStatusCode() == HttpStatus.NOT_MODIFIED) {
			return Mono.empty();
		}
		return CACHE_HEADERS.writeHttpHeaders(exchange);
	}

}
