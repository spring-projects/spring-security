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
public class XXssProtectionServerHttpHeadersWriterTests {

	ServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/").build());

	HttpHeaders headers = exchange.getResponse().getHeaders();

	XXssProtectionServerHttpHeadersWriter writer = new XXssProtectionServerHttpHeadersWriter();

	@Test
	public void writeHeadersWhenNoHeadersThenWriteHeaders() {
		writer.writeHttpHeaders(exchange);

		assertThat(headers).hasSize(1);
		assertThat(headers.get(XXssProtectionServerHttpHeadersWriter.X_XSS_PROTECTION)).containsOnly("1 ; mode=block");
	}

	@Test
	public void writeHeadersWhenBlockFalseThenWriteHeaders() {
		writer.setBlock(false);

		writer.writeHttpHeaders(exchange);

		assertThat(headers).hasSize(1);
		assertThat(headers.get(XXssProtectionServerHttpHeadersWriter.X_XSS_PROTECTION)).containsOnly("1");
	}

	@Test
	public void writeHeadersWhenEnabledFalseThenWriteHeaders() {
		writer.setEnabled(false);

		writer.writeHttpHeaders(exchange);

		assertThat(headers).hasSize(1);
		assertThat(headers.get(XXssProtectionServerHttpHeadersWriter.X_XSS_PROTECTION)).containsOnly("0");
	}

	@Test
	public void writeHeadersWhenHeaderWrittenThenDoesNotOverrride() {
		String headerValue = "value";
		headers.set(XXssProtectionServerHttpHeadersWriter.X_XSS_PROTECTION, headerValue);

		writer.writeHttpHeaders(exchange);

		assertThat(headers).hasSize(1);
		assertThat(headers.get(XXssProtectionServerHttpHeadersWriter.X_XSS_PROTECTION)).containsOnly(headerValue);
	}

}
