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

class CrossOriginOpenerPolicyServerHttpHeadersWriterTests {

	private ServerWebExchange exchange;

	private CrossOriginOpenerPolicyServerHttpHeadersWriter writer;

	@BeforeEach
	void setup() {
		this.exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/"));
		this.writer = new CrossOriginOpenerPolicyServerHttpHeadersWriter();
	}

	@Test
	void setOpenerPolicyWhenNullOpenerPolicyThenThrowsIllegalArgument() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.writer.setPolicy(null))
			.withMessage("openerPolicy cannot be null");
	}

	@Test
	void writeHeadersWhenNoValuesThenDoesNotWriteHeaders() {
		this.writer.writeHttpHeaders(this.exchange);
		HttpHeaders headers = this.exchange.getResponse().getHeaders();
		assertThat(headers.headerNames()).isEmpty();
	}

	@Test
	void writeHeadersWhenResponseHeaderExistsThenDontOverride() {
		this.exchange.getResponse()
			.getHeaders()
			.add(CrossOriginOpenerPolicyServerHttpHeadersWriter.OPENER_POLICY, "same-origin");
		this.writer.writeHttpHeaders(this.exchange);
		HttpHeaders headers = this.exchange.getResponse().getHeaders();
		assertThat(headers.headerNames()).hasSize(1);
		assertThat(headers.get(CrossOriginOpenerPolicyServerHttpHeadersWriter.OPENER_POLICY))
			.containsOnly("same-origin");
	}

	@Test
	void writeHeadersWhenSetHeaderValuesThenWrites() {
		this.writer
			.setPolicy(CrossOriginOpenerPolicyServerHttpHeadersWriter.CrossOriginOpenerPolicy.SAME_ORIGIN_ALLOW_POPUPS);
		this.writer.writeHttpHeaders(this.exchange);
		HttpHeaders headers = this.exchange.getResponse().getHeaders();
		assertThat(headers.headerNames()).hasSize(1);
		assertThat(headers.get(CrossOriginOpenerPolicyServerHttpHeadersWriter.OPENER_POLICY))
			.containsOnly("same-origin-allow-popups");
	}

}
