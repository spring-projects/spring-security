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

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;

/**
 * @author Rob Winch
 * @since 5.0
 */
public class StaticServerHttpHeadersWriterTests {

	StaticServerHttpHeadersWriter writer = StaticServerHttpHeadersWriter.builder()
			.header(ContentTypeOptionsServerHttpHeadersWriter.X_CONTENT_OPTIONS,
					ContentTypeOptionsServerHttpHeadersWriter.NOSNIFF)
			.build();

	ServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/").build());

	HttpHeaders headers = exchange.getResponse().getHeaders();

	@Test
	public void writeHeadersWhenSingleHeaderThenWritesHeader() {
		writer.writeHttpHeaders(exchange);

		assertThat(headers.get(ContentTypeOptionsServerHttpHeadersWriter.X_CONTENT_OPTIONS))
				.containsOnly(ContentTypeOptionsServerHttpHeadersWriter.NOSNIFF);
	}

	@Test
	public void writeHeadersWhenSingleHeaderAndHeaderWrittenThenSuccess() {
		String headerValue = "other";
		headers.set(ContentTypeOptionsServerHttpHeadersWriter.X_CONTENT_OPTIONS, headerValue);

		writer.writeHttpHeaders(exchange);

		assertThat(headers.get(ContentTypeOptionsServerHttpHeadersWriter.X_CONTENT_OPTIONS)).containsOnly(headerValue);
	}

	@Test
	public void writeHeadersWhenMultiHeaderThenWritesAllHeaders() {
		writer = StaticServerHttpHeadersWriter.builder()
				.header(HttpHeaders.CACHE_CONTROL, CacheControlServerHttpHeadersWriter.CACHE_CONTRTOL_VALUE)
				.header(HttpHeaders.PRAGMA, CacheControlServerHttpHeadersWriter.PRAGMA_VALUE)
				.header(HttpHeaders.EXPIRES, CacheControlServerHttpHeadersWriter.EXPIRES_VALUE).build();

		writer.writeHttpHeaders(exchange);

		assertThat(headers.get(HttpHeaders.CACHE_CONTROL))
				.containsOnly(CacheControlServerHttpHeadersWriter.CACHE_CONTRTOL_VALUE);
		assertThat(headers.get(HttpHeaders.PRAGMA)).containsOnly(CacheControlServerHttpHeadersWriter.PRAGMA_VALUE);
		assertThat(headers.get(HttpHeaders.EXPIRES)).containsOnly(CacheControlServerHttpHeadersWriter.EXPIRES_VALUE);
	}

	@Test
	public void writeHeadersWhenMultiHeaderAndSingleWrittenThenNoHeadersOverridden() {
		String headerValue = "other";
		headers.set(HttpHeaders.CACHE_CONTROL, headerValue);

		writer = StaticServerHttpHeadersWriter.builder()
				.header(HttpHeaders.CACHE_CONTROL, CacheControlServerHttpHeadersWriter.CACHE_CONTRTOL_VALUE)
				.header(HttpHeaders.PRAGMA, CacheControlServerHttpHeadersWriter.PRAGMA_VALUE)
				.header(HttpHeaders.EXPIRES, CacheControlServerHttpHeadersWriter.EXPIRES_VALUE).build();

		writer.writeHttpHeaders(exchange);

		assertThat(headers).hasSize(1);
		assertThat(headers.get(HttpHeaders.CACHE_CONTROL)).containsOnly(headerValue);
	}

}
