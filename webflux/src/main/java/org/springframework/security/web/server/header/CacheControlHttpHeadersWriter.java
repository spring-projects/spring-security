/*
 *
 * Copyright 2002-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package org.springframework.security.web.server.header;

import org.springframework.http.HttpHeaders;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

/**
 *
 * @author Rob Winch
 * @since 5.0
 */
public class CacheControlHttpHeadersWriter implements HttpHeadersWriter {

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
	private static final HttpHeadersWriter CACHE_HEADERS = StaticHttpHeadersWriter.builder()
			.header(HttpHeaders.CACHE_CONTROL, CacheControlHttpHeadersWriter.CACHE_CONTRTOL_VALUE)
			.header(HttpHeaders.PRAGMA,  CacheControlHttpHeadersWriter.PRAGMA_VALUE)
			.header(HttpHeaders.EXPIRES,  CacheControlHttpHeadersWriter.EXPIRES_VALUE)
			.build();

	@Override
	public Mono<Void> writeHttpHeaders(ServerWebExchange exchange) {
		return CACHE_HEADERS.writeHttpHeaders(exchange);
	}

}
