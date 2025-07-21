/*
 * Copyright 2002-2023 the original author or authors.
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

import org.junit.jupiter.api.Test;

import org.springframework.http.HttpHeaders;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link ContentTypeOptionsServerHttpHeadersWriter}
 *
 * @author Marcus da Coregio
 */
class ContentTypeOptionsServerHttpHeadersWriterTests {

	ContentTypeOptionsServerHttpHeadersWriter writer = new ContentTypeOptionsServerHttpHeadersWriter();

	ServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/").build());

	HttpHeaders headers = this.exchange.getResponse().getHeaders();

	@Test
	void writeHeadersWhenNoHeadersThenWriteHeaders() {
		this.writer.writeHttpHeaders(this.exchange);
		assertThat(this.headers.headerNames()).hasSize(1);
		assertThat(this.headers.get(ContentTypeOptionsServerHttpHeadersWriter.X_CONTENT_OPTIONS))
			.containsOnly(ContentTypeOptionsServerHttpHeadersWriter.NOSNIFF);
	}

	@Test
	void writeHeadersWhenHeaderWrittenThenDoesNotOverride() {
		String headerValue = "value";
		this.headers.set(ContentTypeOptionsServerHttpHeadersWriter.X_CONTENT_OPTIONS, headerValue);
		this.writer.writeHttpHeaders(this.exchange);
		assertThat(this.headers.headerNames()).hasSize(1);
		assertThat(this.headers.get(ContentTypeOptionsServerHttpHeadersWriter.X_CONTENT_OPTIONS))
			.containsOnly(headerValue);
	}

	@Test
	void constantsMatchExpectedHeaderAndValue() {
		assertThat(ContentTypeOptionsServerHttpHeadersWriter.X_CONTENT_OPTIONS).isEqualTo("X-Content-Type-Options");
		assertThat(ContentTypeOptionsServerHttpHeadersWriter.NOSNIFF).isEqualTo("nosniff");
	}

}
