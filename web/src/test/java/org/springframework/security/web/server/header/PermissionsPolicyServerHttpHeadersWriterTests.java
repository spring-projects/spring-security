/*
 * Copyright 2002-2020 the original author or authors.
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

/**
 * Tests for {@link PermissionsPolicyServerHttpHeadersWriter}.
 *
 * @author Christophe Gilles
 */
public class PermissionsPolicyServerHttpHeadersWriterTests {

	private static final String DEFAULT_POLICY_DIRECTIVES = "geolocation=(self)";

	private ServerWebExchange exchange;

	private PermissionsPolicyServerHttpHeadersWriter writer;

	@BeforeEach
	public void setup() {
		this.exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/"));
		this.writer = new PermissionsPolicyServerHttpHeadersWriter();
	}

	@Test
	public void writeHeadersWhenUsingDefaultsThenDoesNotWrite() {
		this.writer.writeHttpHeaders(this.exchange);
		HttpHeaders headers = this.exchange.getResponse().getHeaders();
		assertThat(headers.headerNames()).isEmpty();
	}

	@Test
	public void writeHeadersWhenUsingPolicyThenWritesPolicy() {
		this.writer.setPolicy(DEFAULT_POLICY_DIRECTIVES);
		this.writer.writeHttpHeaders(this.exchange);
		HttpHeaders headers = this.exchange.getResponse().getHeaders();
		assertThat(headers.headerNames()).hasSize(1);
		assertThat(headers.get(PermissionsPolicyServerHttpHeadersWriter.PERMISSIONS_POLICY))
			.containsOnly(DEFAULT_POLICY_DIRECTIVES);
	}

	@Test
	public void writeHeadersWhenAlreadyWrittenThenWritesHeader() {
		this.writer.setPolicy(DEFAULT_POLICY_DIRECTIVES);
		String headerValue = "camera=(self)";
		this.exchange.getResponse()
			.getHeaders()
			.set(PermissionsPolicyServerHttpHeadersWriter.PERMISSIONS_POLICY, headerValue);
		this.writer.writeHttpHeaders(this.exchange);
		HttpHeaders headers = this.exchange.getResponse().getHeaders();
		assertThat(headers.headerNames()).hasSize(1);
		assertThat(headers.get(PermissionsPolicyServerHttpHeadersWriter.PERMISSIONS_POLICY)).containsOnly(headerValue);
	}

}
