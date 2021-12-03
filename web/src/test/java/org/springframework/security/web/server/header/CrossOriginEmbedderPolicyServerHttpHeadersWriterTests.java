/*
 * Copyright 2002-2021 the original author or authors.
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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.http.HttpHeaders;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

class CrossOriginEmbedderPolicyServerHttpHeadersWriterTests {

	private ServerWebExchange exchange;

	private CrossOriginEmbedderPolicyServerHttpHeadersWriter writer;

	@BeforeEach
	void setup() {
		this.exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/"));
		this.writer = new CrossOriginEmbedderPolicyServerHttpHeadersWriter();
	}

	@Test
	void setEmbedderPolicyWhenNullEmbedderPolicyThenThrowsIllegalArgument() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.writer.setPolicy(null))
				.withMessage("embedderPolicy cannot be null");
	}

	@Test
	void writeHeadersWhenNoValuesThenDoesNotWriteHeaders() {
		this.writer.writeHttpHeaders(this.exchange);
		HttpHeaders headers = this.exchange.getResponse().getHeaders();
		assertThat(headers).isEmpty();
	}

	@Test
	void writeHeadersWhenResponseHeaderExistsThenDontOverride() {
		this.exchange.getResponse().getHeaders().add(CrossOriginEmbedderPolicyServerHttpHeadersWriter.EMBEDDER_POLICY,
				"require-corp");
		this.writer.writeHttpHeaders(this.exchange);
		HttpHeaders headers = this.exchange.getResponse().getHeaders();
		assertThat(headers).hasSize(1);
		assertThat(headers.get(CrossOriginEmbedderPolicyServerHttpHeadersWriter.EMBEDDER_POLICY))
				.containsOnly("require-corp");
	}

	@Test
	void writeHeadersWhenSetHeaderValuesThenWrites() {
		this.writer.setPolicy(CrossOriginEmbedderPolicyServerHttpHeadersWriter.CrossOriginEmbedderPolicy.REQUIRE_CORP);
		this.writer.writeHttpHeaders(this.exchange);
		HttpHeaders headers = this.exchange.getResponse().getHeaders();
		assertThat(headers).hasSize(1);
		assertThat(headers.get(CrossOriginEmbedderPolicyServerHttpHeadersWriter.EMBEDDER_POLICY))
				.containsOnly("require-corp");
	}

}
