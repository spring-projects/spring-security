/*
 * Copyright 2002-2022 the original author or authors.
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
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * @author Rob Winch
 * @since 5.0
 */
public class XXssProtectionServerHttpHeadersWriterTests {

	ServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/").build());

	HttpHeaders headers = this.exchange.getResponse().getHeaders();

	XXssProtectionServerHttpHeadersWriter writer = new XXssProtectionServerHttpHeadersWriter();

	@Test
	void setHeaderValueNullThenThrowsIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.writer.setHeaderValue(null))
				.withMessage("headerValue cannot be null");
	}

	@Test
	public void writeHeadersWhenNoHeadersThenWriteHeaders() {
		this.writer.writeHttpHeaders(this.exchange);
		assertThat(this.headers).hasSize(1);
		assertThat(this.headers.get(XXssProtectionServerHttpHeadersWriter.X_XSS_PROTECTION)).containsOnly("0");
	}

	@Test
	public void writeHeadersWhenHeaderWrittenThenDoesNotOverrride() {
		String headerValue = "value";
		this.headers.set(XXssProtectionServerHttpHeadersWriter.X_XSS_PROTECTION, headerValue);
		this.writer.writeHttpHeaders(this.exchange);
		assertThat(this.headers).hasSize(1);
		assertThat(this.headers.get(XXssProtectionServerHttpHeadersWriter.X_XSS_PROTECTION)).containsOnly(headerValue);
	}

	@Test
	void writeHeadersWhenDisabledThenWriteHeaders() {
		this.writer.setHeaderValue(XXssProtectionServerHttpHeadersWriter.HeaderValue.DISABLED);
		this.writer.writeHttpHeaders(this.exchange);
		assertThat(this.headers).hasSize(1);
		assertThat(this.headers.get(XXssProtectionServerHttpHeadersWriter.X_XSS_PROTECTION)).containsOnly("0");
	}

	@Test
	void writeHeadersWhenEnabledThenWriteHeaders() {
		this.writer.setHeaderValue(XXssProtectionServerHttpHeadersWriter.HeaderValue.ENABLED);
		this.writer.writeHttpHeaders(this.exchange);
		assertThat(this.headers).hasSize(1);
		assertThat(this.headers.get(XXssProtectionServerHttpHeadersWriter.X_XSS_PROTECTION)).containsOnly("1");
	}

	@Test
	void writeHeadersWhenEnabledModeBlockThenWriteHeaders() {
		this.writer.setHeaderValue(XXssProtectionServerHttpHeadersWriter.HeaderValue.ENABLED_MODE_BLOCK);
		this.writer.writeHttpHeaders(this.exchange);
		assertThat(this.headers).hasSize(1);
		assertThat(this.headers.get(XXssProtectionServerHttpHeadersWriter.X_XSS_PROTECTION))
				.containsOnly("1 ; mode=block");
	}

}
