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

package org.springframework.security.web.server;

import java.net.URI;

import org.assertj.core.api.ThrowingConsumer;
import org.junit.jupiter.api.Test;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.http.server.reactive.MockServerHttpResponse;
import org.springframework.mock.web.server.MockServerWebExchange;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link FormPostServerRedirectStrategy}.
 *
 * @author Max Batischev
 */
public class FormPostServerRedirectStrategyTests {

	private static final String POLICY_DIRECTIVE_PATTERN = "script-src 'nonce-(.+)'";

	private final ServerRedirectStrategy redirectStrategy = new FormPostServerRedirectStrategy();

	private final MockServerHttpRequest request = MockServerHttpRequest.get("https://localhost").build();

	private final MockServerWebExchange webExchange = MockServerWebExchange.from(this.request);

	@Test
	public void redirectWhetLocationAbsoluteUriIsPresentThenRedirect() {
		this.redirectStrategy.sendRedirect(this.webExchange, URI.create("https://example.com")).block();

		MockServerHttpResponse response = this.webExchange.getResponse();
		assertThat(response.getBodyAsString().block()).contains("action=\"https://example.com\"");
		assertThat(this.webExchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.OK);
		assertThat(this.webExchange.getResponse().getHeaders().getContentType()).isEqualTo(MediaType.TEXT_HTML);
		assertThat(this.webExchange.getResponse()).satisfies(hasScriptSrcNonce());
	}

	@Test
	public void redirectWhetLocationRootRelativeUriIsPresentThenRedirect() {
		this.redirectStrategy.sendRedirect(this.webExchange, URI.create("/test")).block();

		MockServerHttpResponse response = this.webExchange.getResponse();
		assertThat(response.getBodyAsString().block()).contains("action=\"/test\"");
		assertThat(this.webExchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.OK);
		assertThat(this.webExchange.getResponse().getHeaders().getContentType()).isEqualTo(MediaType.TEXT_HTML);
		assertThat(this.webExchange.getResponse()).satisfies(hasScriptSrcNonce());
	}

	@Test
	public void redirectWhetLocationRelativeUriIsPresentThenRedirect() {
		this.redirectStrategy.sendRedirect(this.webExchange, URI.create("test")).block();

		MockServerHttpResponse response = this.webExchange.getResponse();
		assertThat(response.getBodyAsString().block()).contains("action=\"test\"");
		assertThat(this.webExchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.OK);
		assertThat(this.webExchange.getResponse().getHeaders().getContentType()).isEqualTo(MediaType.TEXT_HTML);
		assertThat(this.webExchange.getResponse()).satisfies(hasScriptSrcNonce());
	}

	@Test
	public void redirectWhenLocationAbsoluteUriWithFragmentIsPresentThenRedirect() {
		this.redirectStrategy.sendRedirect(this.webExchange, URI.create("https://example.com/path#fragment")).block();

		MockServerHttpResponse response = this.webExchange.getResponse();
		assertThat(response.getBodyAsString().block()).contains("action=\"https://example.com/path#fragment\"");
		assertThat(this.webExchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.OK);
		assertThat(this.webExchange.getResponse().getHeaders().getContentType()).isEqualTo(MediaType.TEXT_HTML);
		assertThat(this.webExchange.getResponse()).satisfies(hasScriptSrcNonce());
	}

	@Test
	public void redirectWhenLocationAbsoluteUriWithQueryParamsIsPresentThenRedirect() {
		this.redirectStrategy
			.sendRedirect(this.webExchange, URI.create("https://example.com/path?param1=one&param2=two#fragment"))
			.block();

		MockServerHttpResponse response = this.webExchange.getResponse();
		String content = response.getBodyAsString().block();
		assertThat(this.webExchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.OK);
		assertThat(this.webExchange.getResponse().getHeaders().getContentType()).isEqualTo(MediaType.TEXT_HTML);
		assertThat(content).contains("action=\"https://example.com/path#fragment\"");
		assertThat(content).contains("<input name=\"param1\" type=\"hidden\" value=\"one\" />");
		assertThat(content).contains("<input name=\"param2\" type=\"hidden\" value=\"two\" />");
	}

	private ThrowingConsumer<MockServerHttpResponse> hasScriptSrcNonce() {
		return (response) -> {
			final String policyDirective = response.getHeaders().getFirst("Content-Security-Policy");
			assertThat(policyDirective).isNotEmpty();
			assertThat(policyDirective).matches(POLICY_DIRECTIVE_PATTERN);

			final String nonce = policyDirective.replaceFirst(POLICY_DIRECTIVE_PATTERN, "$1");
			assertThat(response.getBodyAsString().block()).contains("<script nonce=\"%s\">".formatted(nonce));
		};
	}

}
