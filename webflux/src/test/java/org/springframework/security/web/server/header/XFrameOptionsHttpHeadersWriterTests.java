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

import org.junit.Before;
import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.web.server.ServerWebExchange;

/**
 * @author Rob Winch
 * @since 5.0
 */
public class XFrameOptionsHttpHeadersWriterTests {

	ServerWebExchange exchange = MockServerHttpRequest.get("/").toExchange();

	XFrameOptionsHttpHeadersWriter writer;

	@Before
	public void setup() {
		writer = new XFrameOptionsHttpHeadersWriter();
	}

	@Test
	public void writeHeadersWhenUsingDefaultsThenWritesDeny() {
		writer.writeHttpHeaders(exchange);

		HttpHeaders headers = exchange.getResponse().getHeaders();
		assertThat(headers).hasSize(1);
		assertThat(headers.get(XFrameOptionsHttpHeadersWriter.X_FRAME_OPTIONS)).containsOnly("DENY");
	}

	@Test
	public void writeHeadersWhenUsingExplicitDenyThenWritesDeny() {
		writer.setMode(XFrameOptionsHttpHeadersWriter.Mode.DENY);

		writer.writeHttpHeaders(exchange);

		HttpHeaders headers = exchange.getResponse().getHeaders();
		assertThat(headers).hasSize(1);
		assertThat(headers.get(XFrameOptionsHttpHeadersWriter.X_FRAME_OPTIONS)).containsOnly("DENY");
	}

	@Test
	public void writeHeadersWhenUsingSameOriginThenWritesSameOrigin() {
		writer.setMode(XFrameOptionsHttpHeadersWriter.Mode.SAMEORIGIN);

		writer.writeHttpHeaders(exchange);

		HttpHeaders headers = exchange.getResponse().getHeaders();
		assertThat(headers).hasSize(1);
		assertThat(headers.get(XFrameOptionsHttpHeadersWriter.X_FRAME_OPTIONS)).containsOnly("SAMEORIGIN");
	}

	@Test
	public void writeHeadersWhenAlreadyWrittenThenWritesHeader() {
		String headerValue = "other";
		exchange.getResponse().getHeaders().set(XFrameOptionsHttpHeadersWriter.X_FRAME_OPTIONS, headerValue);

		writer.writeHttpHeaders(exchange);

		HttpHeaders headers = exchange.getResponse().getHeaders();
		assertThat(headers).hasSize(1);
		assertThat(headers.get(XFrameOptionsHttpHeadersWriter.X_FRAME_OPTIONS)).containsOnly(headerValue);
	}

}
