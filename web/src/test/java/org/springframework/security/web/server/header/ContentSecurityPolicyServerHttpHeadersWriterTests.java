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

import org.junit.Before;
import org.junit.Test;

import org.springframework.http.HttpHeaders;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link ContentSecurityPolicyServerHttpHeadersWriter}.
 *
 * @author Vedran Pavic
 */
public class ContentSecurityPolicyServerHttpHeadersWriterTests {

	private static final String DEFAULT_POLICY_DIRECTIVES = "default-src 'self'";

	private ServerWebExchange exchange;

	private ContentSecurityPolicyServerHttpHeadersWriter writer;

	@Before
	public void setup() {
		this.exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/"));
		this.writer = new ContentSecurityPolicyServerHttpHeadersWriter();
	}

	@Test
	public void writeHeadersWhenUsingDefaultsThenDoesNotWrite() {
		this.writer.writeHttpHeaders(this.exchange);

		HttpHeaders headers = this.exchange.getResponse().getHeaders();
		assertThat(headers).isEmpty();
	}

	@Test
	public void writeHeadersWhenUsingPolicyThenWritesPolicy() {
		this.writer.setPolicyDirectives(DEFAULT_POLICY_DIRECTIVES);
		this.writer.writeHttpHeaders(this.exchange);

		HttpHeaders headers = this.exchange.getResponse().getHeaders();
		assertThat(headers).hasSize(1);
		assertThat(headers.get(ContentSecurityPolicyServerHttpHeadersWriter.CONTENT_SECURITY_POLICY))
				.containsOnly(DEFAULT_POLICY_DIRECTIVES);
	}

	@Test
	public void writeHeadersWhenReportPolicyThenWritesReportPolicy() {
		this.writer.setPolicyDirectives(DEFAULT_POLICY_DIRECTIVES);
		this.writer.setReportOnly(true);
		this.writer.writeHttpHeaders(this.exchange);

		HttpHeaders headers = this.exchange.getResponse().getHeaders();
		assertThat(headers).hasSize(1);
		assertThat(headers.get(ContentSecurityPolicyServerHttpHeadersWriter.CONTENT_SECURITY_POLICY_REPORT_ONLY))
				.containsOnly(DEFAULT_POLICY_DIRECTIVES);
	}

	@Test
	public void writeHeadersWhenOnlyReportOnlySetThenDoesNotWrite() {
		this.writer.setReportOnly(true);
		this.writer.writeHttpHeaders(this.exchange);

		HttpHeaders headers = this.exchange.getResponse().getHeaders();
		assertThat(headers).isEmpty();
	}

	@Test
	public void writeHeadersWhenAlreadyWrittenThenWritesHeader() {
		String headerValue = "default-src https: 'self'";
		this.exchange.getResponse().getHeaders()
				.set(ContentSecurityPolicyServerHttpHeadersWriter.CONTENT_SECURITY_POLICY, headerValue);
		this.writer.writeHttpHeaders(this.exchange);

		HttpHeaders headers = this.exchange.getResponse().getHeaders();
		assertThat(headers).hasSize(1);
		assertThat(headers.get(ContentSecurityPolicyServerHttpHeadersWriter.CONTENT_SECURITY_POLICY))
				.containsOnly(headerValue);
	}

}
