/*
 * Copyright 2002-2025 the original author or authors.
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
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import reactor.core.publisher.Mono;

import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.HtmlUtils;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * Redirect using an auto-submitting HTML form using the POST method. All query params
 * provided in the URL are changed to inputs in the form so they are submitted as POST
 * data instead of query string data.
 *
 * @author Max Batischev
 * @since 6.5
 */
public final class ServerFormPostRedirectStrategy implements ServerRedirectStrategy {

	private static final String CONTENT_SECURITY_POLICY_HEADER = "Content-Security-Policy";

	private static final StringKeyGenerator DEFAULT_NONCE_GENERATOR = new Base64StringKeyGenerator(
			Base64.getUrlEncoder().withoutPadding(), 96);

	private static final String REDIRECT_PAGE_TEMPLATE = """
			<!DOCTYPE html>
			<html lang="en">
			  <head>
			    <meta charset="utf-8">
			    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
			    <meta name="description" content="">
			    <meta name="author" content="">
			    <title>Redirect</title>
			  </head>
			  <body>
			    <form id="redirect-form" method="POST" action="{{action}}">
			      {{params}}
			      <noscript>
			        <p>JavaScript is not enabled for this page.</p>
			        <button type="submit">Click to continue</button>
			      </noscript>
			    </form>
			    <script nonce="{{nonce}}">
			      document.getElementById("redirect-form").submit();
			    </script>
			  </body>
			</html>
			""";

	private static final String HIDDEN_INPUT_TEMPLATE = """
			<input name="{{name}}" type="hidden" value="{{value}}" />
			""";

	@Override
	public Mono<Void> sendRedirect(ServerWebExchange exchange, URI location) {
		String nonce = DEFAULT_NONCE_GENERATOR.generateKey();
		String policyDirective = "script-src 'nonce-%s'".formatted(nonce);

		ServerHttpResponse response = exchange.getResponse();
		response.setStatusCode(HttpStatus.OK);
		response.getHeaders().setContentType(MediaType.TEXT_HTML);
		response.getHeaders().add(CONTENT_SECURITY_POLICY_HEADER, policyDirective);
		return response.writeWith(createBuffer(exchange, location, nonce));
	}

	private Mono<DataBuffer> createBuffer(ServerWebExchange exchange, URI location, String nonce) {
		byte[] bytes = createPage(location, nonce);
		DataBufferFactory bufferFactory = exchange.getResponse().bufferFactory();
		return Mono.just(bufferFactory.wrap(bytes));
	}

	private byte[] createPage(URI location, String nonce) {
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUri(location);

		StringBuilder hiddenInputsHtmlBuilder = new StringBuilder();
		for (final Map.Entry<String, List<String>> entry : uriComponentsBuilder.build().getQueryParams().entrySet()) {
			final String name = entry.getKey();
			for (final String value : entry.getValue()) {
				// @formatter:off
				final String hiddenInput = HIDDEN_INPUT_TEMPLATE
						.replace("{{name}}", HtmlUtils.htmlEscape(name))
						.replace("{{value}}", HtmlUtils.htmlEscape(value));
				// @formatter:on
				hiddenInputsHtmlBuilder.append(hiddenInput.trim());
			}
		}
		// @formatter:off
		return REDIRECT_PAGE_TEMPLATE
				.replace("{{action}}", HtmlUtils.htmlEscape(uriComponentsBuilder.query(null).build().toUriString()))
				.replace("{{params}}", hiddenInputsHtmlBuilder.toString())
				.replace("{{nonce}}", HtmlUtils.htmlEscape(nonce))
				.getBytes(StandardCharsets.UTF_8);
		// @formatter:on
	}

}
