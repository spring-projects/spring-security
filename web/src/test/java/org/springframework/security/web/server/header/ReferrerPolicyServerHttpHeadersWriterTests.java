/*
 * Copyright 2002-2018 the original author or authors.
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
import org.springframework.security.web.server.header.ReferrerPolicyServerHttpHeadersWriter.ReferrerPolicy;
import org.springframework.web.server.ServerWebExchange;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link ReferrerPolicyServerHttpHeadersWriter}.
 *
 * @author Vedran Pavic
 */
public class ReferrerPolicyServerHttpHeadersWriterTests {

	private ServerWebExchange exchange;

	private ReferrerPolicyServerHttpHeadersWriter writer;

	@BeforeEach
	public void setup() {
		this.exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/"));
		this.writer = new ReferrerPolicyServerHttpHeadersWriter();
	}

	@Test
	public void writeHeadersWhenUsingDefaultsThenDoesNotWrite() {
		this.writer.writeHttpHeaders(this.exchange);
		HttpHeaders headers = this.exchange.getResponse().getHeaders();
		assertThat(headers).hasSize(1);
		assertThat(headers.get(ReferrerPolicyServerHttpHeadersWriter.REFERRER_POLICY))
				.containsOnly(ReferrerPolicy.NO_REFERRER.getPolicy());
	}

	@Test
	public void writeHeadersWhenUsingPolicyThenWritesPolicy() {
		this.writer.setPolicy(ReferrerPolicy.SAME_ORIGIN);
		this.writer.writeHttpHeaders(this.exchange);
		HttpHeaders headers = this.exchange.getResponse().getHeaders();
		assertThat(headers).hasSize(1);
		assertThat(headers.get(ReferrerPolicyServerHttpHeadersWriter.REFERRER_POLICY))
				.containsOnly(ReferrerPolicy.SAME_ORIGIN.getPolicy());
	}

	@Test
	public void writeHeadersWhenAlreadyWrittenThenWritesHeader() {
		String headerValue = ReferrerPolicy.SAME_ORIGIN.getPolicy();
		this.exchange.getResponse().getHeaders().set(ReferrerPolicyServerHttpHeadersWriter.REFERRER_POLICY,
				headerValue);
		this.writer.writeHttpHeaders(this.exchange);
		HttpHeaders headers = this.exchange.getResponse().getHeaders();
		assertThat(headers).hasSize(1);
		assertThat(headers.get(ReferrerPolicyServerHttpHeadersWriter.REFERRER_POLICY)).containsOnly(headerValue);
	}

}
