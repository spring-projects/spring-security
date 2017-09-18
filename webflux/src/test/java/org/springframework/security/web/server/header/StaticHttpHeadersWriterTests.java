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

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.web.server.ServerWebExchange;

/**
 * @author Rob Winch
 * @since 5.0
 */
public class StaticHttpHeadersWriterTests {

	StaticHttpHeadersWriter writer = StaticHttpHeadersWriter.builder()
			.header(ContentTypeOptionsHttpHeadersWriter.X_CONTENT_OPTIONS, ContentTypeOptionsHttpHeadersWriter.NOSNIFF)
			.build();

	ServerWebExchange exchange = MockServerHttpRequest.get("/").toExchange();

	HttpHeaders headers = exchange.getResponse().getHeaders();

	@Test
	public void writeHeadersWhenSingleHeaderThenWritesHeader() {
		writer.writeHttpHeaders(exchange);

		assertThat(headers.get(ContentTypeOptionsHttpHeadersWriter.X_CONTENT_OPTIONS)).containsOnly(ContentTypeOptionsHttpHeadersWriter.NOSNIFF);
	}

	@Test
	public void writeHeadersWhenSingleHeaderAndHeaderWrittenThenSuccess() {
		String headerValue = "other";
		headers.set(ContentTypeOptionsHttpHeadersWriter.X_CONTENT_OPTIONS, headerValue);

		writer.writeHttpHeaders(exchange);

		assertThat(headers.get(ContentTypeOptionsHttpHeadersWriter.X_CONTENT_OPTIONS)).containsOnly(headerValue);
	}

	@Test
	public void writeHeadersWhenMultiHeaderThenWritesAllHeaders() {
		writer = StaticHttpHeadersWriter.builder()
					.header(HttpHeaders.CACHE_CONTROL, CacheControlHttpHeadersWriter.CACHE_CONTRTOL_VALUE)
					.header(HttpHeaders.PRAGMA,  CacheControlHttpHeadersWriter.PRAGMA_VALUE)
					.header(HttpHeaders.EXPIRES,  CacheControlHttpHeadersWriter.EXPIRES_VALUE)
					.build();

		writer.writeHttpHeaders(exchange);

		assertThat(headers.get(HttpHeaders.CACHE_CONTROL)).containsOnly(CacheControlHttpHeadersWriter.CACHE_CONTRTOL_VALUE);
		assertThat(headers.get(HttpHeaders.PRAGMA)).containsOnly(CacheControlHttpHeadersWriter.PRAGMA_VALUE);
		assertThat(headers.get(HttpHeaders.EXPIRES)).containsOnly(CacheControlHttpHeadersWriter.EXPIRES_VALUE);
	}

	@Test
	public void writeHeadersWhenMultiHeaderAndSingleWrittenThenNoHeadersOverridden() {
		String headerValue = "other";
		headers.set(HttpHeaders.CACHE_CONTROL, headerValue);

		writer = StaticHttpHeadersWriter.builder()
					.header(HttpHeaders.CACHE_CONTROL, CacheControlHttpHeadersWriter.CACHE_CONTRTOL_VALUE)
					.header(HttpHeaders.PRAGMA,  CacheControlHttpHeadersWriter.PRAGMA_VALUE)
					.header(HttpHeaders.EXPIRES,  CacheControlHttpHeadersWriter.EXPIRES_VALUE)
					.build();

		writer.writeHttpHeaders(exchange);

		assertThat(headers).hasSize(1);
		assertThat(headers.get(HttpHeaders.CACHE_CONTROL)).containsOnly(headerValue);
	}
}
