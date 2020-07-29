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

import org.junit.Test;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Rob Winch
 * @since 5.0
 *
 */
public class CacheControlServerHttpHeadersWriterTests {

	CacheControlServerHttpHeadersWriter writer = new CacheControlServerHttpHeadersWriter();

	ServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/").build());

	HttpHeaders headers = this.exchange.getResponse().getHeaders();

	@Test
	public void writeHeadersWhenCacheHeadersThenWritesAllCacheControl() {
		this.writer.writeHttpHeaders(this.exchange);

		assertThat(this.headers).hasSize(3);
		assertThat(this.headers.get(HttpHeaders.CACHE_CONTROL))
				.containsOnly(CacheControlServerHttpHeadersWriter.CACHE_CONTRTOL_VALUE);
		assertThat(this.headers.get(HttpHeaders.EXPIRES))
				.containsOnly(CacheControlServerHttpHeadersWriter.EXPIRES_VALUE);
		assertThat(this.headers.get(HttpHeaders.PRAGMA)).containsOnly(CacheControlServerHttpHeadersWriter.PRAGMA_VALUE);
	}

	@Test
	public void writeHeadersWhenCacheControlThenNoCacheControlHeaders() {
		String cacheControl = "max-age=1234";

		this.headers.set(HttpHeaders.CACHE_CONTROL, cacheControl);

		this.writer.writeHttpHeaders(this.exchange);

		assertThat(this.headers.get(HttpHeaders.CACHE_CONTROL)).containsOnly(cacheControl);
	}

	@Test
	public void writeHeadersWhenPragmaThenNoCacheControlHeaders() {
		String pragma = "1";
		this.headers.set(HttpHeaders.PRAGMA, pragma);

		this.writer.writeHttpHeaders(this.exchange);

		assertThat(this.headers).hasSize(1);
		assertThat(this.headers.get(HttpHeaders.PRAGMA)).containsOnly(pragma);
	}

	@Test
	public void writeHeadersWhenExpiresThenNoCacheControlHeaders() {
		String expires = "1";
		this.headers.set(HttpHeaders.EXPIRES, expires);

		this.writer.writeHttpHeaders(this.exchange);

		assertThat(this.headers).hasSize(1);
		assertThat(this.headers.get(HttpHeaders.EXPIRES)).containsOnly(expires);
	}

	@Test
	// gh-5534
	public void writeHeadersWhenNotModifiedThenNoCacheControlHeaders() {
		this.exchange.getResponse().setStatusCode(HttpStatus.NOT_MODIFIED);

		this.writer.writeHttpHeaders(this.exchange);

		assertThat(this.headers).isEmpty();
	}

}
