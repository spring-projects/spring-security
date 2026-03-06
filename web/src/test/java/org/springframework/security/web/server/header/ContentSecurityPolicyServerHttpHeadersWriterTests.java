/*
 * Copyright 2004-present the original author or authors.
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
import reactor.test.StepVerifier;

import org.springframework.http.HttpHeaders;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link ContentSecurityPolicyServerHttpHeadersWriter}.
 *
 * @author Vedran Pavic
 * @author Ziqin Wang
 */
public class ContentSecurityPolicyServerHttpHeadersWriterTests {

	private static final String CONTENT_SECURITY_POLICY_HEADER = "Content-Security-Policy";

	private static final String CONTENT_SECURITY_POLICY_REPORT_ONLY_HEADER = "Content-Security-Policy-Report-Only";

	private static final String DEFAULT_POLICY_DIRECTIVES = "default-src 'self'";

	private static final String DEFAULT_NONCE_ATTRIBUTE_NAME = "_csp_nonce";

	private ServerWebExchange exchange;

	private ContentSecurityPolicyServerHttpHeadersWriter writer;

	@BeforeEach
	public void setup() {
		this.exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/"));
		this.writer = new ContentSecurityPolicyServerHttpHeadersWriter();
	}

	@Test
	public void writeHeadersWhenUsingDefaultsThenDoesNotWrite() {
		StepVerifier.create(this.writer.writeHttpHeaders(this.exchange)).verifyComplete();
		HttpHeaders headers = this.exchange.getResponse().getHeaders();
		assertThat(headers.headerNames()).isEmpty();
	}

	@Test
	public void writeHeadersWhenUsingPolicyThenWritesPolicy() {
		this.writer.setPolicyDirectives(DEFAULT_POLICY_DIRECTIVES);
		StepVerifier.create(this.writer.writeHttpHeaders(this.exchange)).verifyComplete();
		HttpHeaders headers = this.exchange.getResponse().getHeaders();
		assertThat(headers.headerNames()).hasSize(1);
		assertThat(headers.get(CONTENT_SECURITY_POLICY_HEADER)).containsOnly(DEFAULT_POLICY_DIRECTIVES);
	}

	@Test
	public void writeHeadersWhenReportPolicyThenWritesReportPolicy() {
		this.writer.setPolicyDirectives(DEFAULT_POLICY_DIRECTIVES);
		this.writer.setReportOnly(true);
		StepVerifier.create(this.writer.writeHttpHeaders(this.exchange)).verifyComplete();
		HttpHeaders headers = this.exchange.getResponse().getHeaders();
		assertThat(headers.headerNames()).hasSize(1);
		assertThat(headers.get(CONTENT_SECURITY_POLICY_REPORT_ONLY_HEADER)).containsOnly(DEFAULT_POLICY_DIRECTIVES);
	}

	@Test
	public void writeHeadersWhenOnlyReportOnlySetThenDoesNotWrite() {
		this.writer.setReportOnly(true);
		StepVerifier.create(this.writer.writeHttpHeaders(this.exchange)).verifyComplete();
		HttpHeaders headers = this.exchange.getResponse().getHeaders();
		assertThat(headers.headerNames()).isEmpty();
	}

	@Test
	public void writeHeadersWhenAlreadyWrittenThenDoesNotOverride() {
		String headerValue = "default-src https: 'self'";
		this.exchange.getResponse().getHeaders().set(CONTENT_SECURITY_POLICY_HEADER, headerValue);
		StepVerifier.create(this.writer.writeHttpHeaders(this.exchange)).verifyComplete();
		HttpHeaders headers = this.exchange.getResponse().getHeaders();
		assertThat(headers.headerNames()).hasSize(1);
		assertThat(headers.get(CONTENT_SECURITY_POLICY_HEADER)).containsOnly(headerValue);
	}

	/** @since 7.1 */
	@Test
	public void whenPolicyDirectivesContainNoncePlaceholderThenWriterIsNonceBased() {
		this.writer.setPolicyDirectives("script-src 'self' 'nonce-{nonce}'");
		assertThat(this.writer.isNonceBased()).isTrue();
		this.writer.setPolicyDirectives("script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'");
		assertThat(this.writer.isNonceBased()).isTrue();
		this.writer.setPolicyDirectives(DEFAULT_POLICY_DIRECTIVES);
		assertThat(this.writer.isNonceBased()).isFalse();
		this.writer.setPolicyDirectives("script-src 'self' 'sha256-A/nonce/without/braces/is/not/a/placeholder='");
		assertThat(this.writer.isNonceBased()).isFalse();
	}

	/** @since 7.1 */
	@Test
	public void writeNonceBasedCspWhenNonceAttributeNameUnsetThenUseDefault() {
		this.writer.setPolicyDirectives("script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'");
		this.exchange.getAttributes().put(DEFAULT_NONCE_ATTRIBUTE_NAME, "Test+Nonce+Value");
		StepVerifier.create(this.writer.writeHttpHeaders(this.exchange)).verifyComplete();
		HttpHeaders headers = this.exchange.getResponse().getHeaders();
		assertThat(headers.get(CONTENT_SECURITY_POLICY_HEADER))
			.containsOnly("script-src 'nonce-Test+Nonce+Value'; style-src 'nonce-Test+Nonce+Value'");
	}

	/** @since 7.1 */
	@Test
	public void writeNonceBasedCspWhenNonceAttributeNameSetThenUseCustomAttribute() {
		String customAttributeName = "custom-attribute-name";
		this.writer.setPolicyDirectives("script-src 'nonce-{nonce}'");
		this.writer.setNonceAttributeName(customAttributeName);
		this.exchange.getAttributes().put(DEFAULT_NONCE_ATTRIBUTE_NAME, "SHOULD+NOT+USE");
		this.exchange.getAttributes().put(customAttributeName, "For/Custom/Nonce/Attribute/Name");
		StepVerifier.create(this.writer.writeHttpHeaders(this.exchange)).verifyComplete();
		HttpHeaders headers = this.exchange.getResponse().getHeaders();
		assertThat(headers.get(CONTENT_SECURITY_POLICY_HEADER))
			.containsOnly("script-src 'nonce-For/Custom/Nonce/Attribute/Name'");
	}

	/** @since 7.1 */
	@Test
	public void writeNonceBasedCspWhenNonceUnsetThenEmitError() {
		this.writer.setPolicyDirectives("script-src 'nonce-{nonce}'");
		this.writer.setNonceAttributeName(DEFAULT_NONCE_ATTRIBUTE_NAME);
		StepVerifier.create(this.writer.writeHttpHeaders(this.exchange))
			.expectErrorSatisfies(
					(ex) -> assertThat(ex).isInstanceOf(IllegalStateException.class).hasMessage("Nonce is unset"))
			.verify();
	}

}
