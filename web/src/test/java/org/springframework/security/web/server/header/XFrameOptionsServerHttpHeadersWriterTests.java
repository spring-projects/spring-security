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

import org.junit.Before;
import org.junit.Test;

import org.springframework.http.HttpHeaders;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Rob Winch
 * @since 5.0
 */
public class XFrameOptionsServerHttpHeadersWriterTests {

	ServerWebExchange exchange = exchange(MockServerHttpRequest.get("/"));

	XFrameOptionsServerHttpHeadersWriter writer;

	@Before
	public void setup() {
		this.writer = new XFrameOptionsServerHttpHeadersWriter();
	}

	@Test
	public void writeHeadersWhenUsingDefaultsThenWritesDeny() {
		this.writer.writeHttpHeaders(this.exchange);

		HttpHeaders headers = this.exchange.getResponse().getHeaders();
		assertThat(headers).hasSize(1);
		assertThat(headers.get(XFrameOptionsServerHttpHeadersWriter.X_FRAME_OPTIONS)).containsOnly("DENY");
	}

	@Test
	public void writeHeadersWhenUsingExplicitDenyThenWritesDeny() {
		this.writer.setMode(XFrameOptionsServerHttpHeadersWriter.Mode.DENY);

		this.writer.writeHttpHeaders(this.exchange);

		HttpHeaders headers = this.exchange.getResponse().getHeaders();
		assertThat(headers).hasSize(1);
		assertThat(headers.get(XFrameOptionsServerHttpHeadersWriter.X_FRAME_OPTIONS)).containsOnly("DENY");
	}

	@Test
	public void writeHeadersWhenUsingSameOriginThenWritesSameOrigin() {
		this.writer.setMode(XFrameOptionsServerHttpHeadersWriter.Mode.SAMEORIGIN);

		this.writer.writeHttpHeaders(this.exchange);

		HttpHeaders headers = this.exchange.getResponse().getHeaders();
		assertThat(headers).hasSize(1);
		assertThat(headers.get(XFrameOptionsServerHttpHeadersWriter.X_FRAME_OPTIONS)).containsOnly("SAMEORIGIN");
	}

	@Test
	public void writeHeadersWhenAlreadyWrittenThenWritesHeader() {
		String headerValue = "other";
		this.exchange.getResponse().getHeaders().set(XFrameOptionsServerHttpHeadersWriter.X_FRAME_OPTIONS, headerValue);

		this.writer.writeHttpHeaders(this.exchange);

		HttpHeaders headers = this.exchange.getResponse().getHeaders();
		assertThat(headers).hasSize(1);
		assertThat(headers.get(XFrameOptionsServerHttpHeadersWriter.X_FRAME_OPTIONS)).containsOnly(headerValue);
	}

	private static MockServerWebExchange exchange(MockServerHttpRequest.BaseBuilder<?> request) {
		return MockServerWebExchange.from(request.build());
	}

}
