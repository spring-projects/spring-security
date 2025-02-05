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

package org.springframework.security.web;

import java.io.IOException;
import java.util.Base64;
import java.util.List;
import java.util.Map.Entry;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.web.util.HtmlUtils;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * Redirect using an auto-submitting HTML form using the POST method. All query params
 * provided in the URL are changed to inputs in the form so they are submitted as POST
 * data instead of query string data.
 *
 * @author Craig Andrews
 * @author Steve Riesenberg
 * @since 6.5
 */
public final class FormPostRedirectStrategy implements RedirectStrategy {

	private static final String CONTENT_SECURITY_POLICY_HEADER = "Content-Security-Policy";

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

	private static final StringKeyGenerator DEFAULT_NONCE_GENERATOR = new Base64StringKeyGenerator(
			Base64.getUrlEncoder().withoutPadding(), 96);

	@Override
	public void sendRedirect(final HttpServletRequest request, final HttpServletResponse response, final String url)
			throws IOException {
		final UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(url);

		final StringBuilder hiddenInputsHtmlBuilder = new StringBuilder();
		for (final Entry<String, List<String>> entry : uriComponentsBuilder.build().getQueryParams().entrySet()) {
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

		// Create the script-src policy directive for the Content-Security-Policy header
		final String nonce = DEFAULT_NONCE_GENERATOR.generateKey();
		final String policyDirective = "script-src 'nonce-%s'".formatted(nonce);

		// @formatter:off
		final String html = REDIRECT_PAGE_TEMPLATE
			// Clear the query string as we don't want that to be part of the form action URL
			.replace("{{action}}", HtmlUtils.htmlEscape(uriComponentsBuilder.query(null).build().toUriString()))
			.replace("{{params}}", hiddenInputsHtmlBuilder.toString())
			.replace("{{nonce}}", HtmlUtils.htmlEscape(nonce));
		// @formatter:on

		response.setStatus(HttpStatus.OK.value());
		response.setContentType(MediaType.TEXT_HTML_VALUE);
		response.setHeader(CONTENT_SECURITY_POLICY_HEADER, policyDirective);
		response.getWriter().write(html);
		response.getWriter().flush();
	}

}
