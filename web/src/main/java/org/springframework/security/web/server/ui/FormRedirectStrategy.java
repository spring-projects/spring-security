/*
 * Copyright 2002-2023 the original author or authors.
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

package org.springframework.security.web.server.ui;

import java.io.IOException;
import java.util.List;
import java.util.Map.Entry;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * Redirect using an autosubmitting HTML form using the POST method. All query params
 * provided in the URL are changed to inputs in the form so they are submitted as POST
 * data instead of query string data.
 */
/* default */ class FormRedirectStrategy implements RedirectStrategy {

	private static final String REDIRECT_PAGE_TEMPLATE = """
			<!DOCTYPE html>
			<html lang="en">
				<head>
					<meta charset="utf-8">
					<meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
					<meta name="description" content="">
					<meta name="author" content="">
					<title>Redirect</title>
					<link href="{{contextPath}}/default-ui.css" rel="stylesheet" />
				</head>
				<body>
				<div class="content">
					<form id="redirectForm" class="redirect-form" method="POST" action="{{action}}">
						{{params}}
						<button class="primary" type="submit">Click to Continue</button>
					</form>
				</div>
				<script src="{{contextPath}}/form-redirect.js"></script>
				</body>
			</html>
			""";

	private static final String HIDDEN_INPUT_TEMPLATE = """
			<input name="{{name}}" type="hidden" value="{{value}}" />
			""";

	@Override
	public void sendRedirect(final HttpServletRequest request, final HttpServletResponse response, final String url)
			throws IOException {
		final UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(url);

		final StringBuilder hiddenInputsHtmlBuilder = new StringBuilder();
		// inputs
		for (final Entry<String, List<String>> entry : uriComponentsBuilder.build().getQueryParams().entrySet()) {
			final String name = entry.getKey();
			for (final String value : entry.getValue()) {
				hiddenInputsHtmlBuilder.append(HtmlTemplates.fromTemplate(HIDDEN_INPUT_TEMPLATE)
					.withValue("name", name)
					.withValue("value", value)
					.render());
			}
		}

		final String html = HtmlTemplates.fromTemplate(REDIRECT_PAGE_TEMPLATE)
			// clear the query string as we don't want that to be part of the form action
			// URL
			.withValue("action", uriComponentsBuilder.query(null).build().toUriString())
			.withRawHtml("params", hiddenInputsHtmlBuilder.toString())
			.withValue("contextPath", request.getContextPath())
			.render();
		response.setStatus(HttpStatus.OK.value());
		response.setContentType(MediaType.TEXT_HTML_VALUE);
		response.getWriter().write(html);
		response.getWriter().flush();
	}

}
