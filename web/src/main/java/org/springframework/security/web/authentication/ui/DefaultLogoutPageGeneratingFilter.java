/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.web.authentication.ui;

import java.io.IOException;
import java.util.Collections;
import java.util.Map;
import java.util.function.Function;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.core.log.LogMessage;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Generates a default log out page.
 *
 * @author Rob Winch
 * @since 5.1
 */
public class DefaultLogoutPageGeneratingFilter extends OncePerRequestFilter {

	private RequestMatcher matcher = new AntPathRequestMatcher("/logout", "GET");

	private Function<HttpServletRequest, Map<String, String>> resolveHiddenInputs = (request) -> Collections.emptyMap();

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		if (this.matcher.matches(request)) {
			renderLogout(request, response);
		}
		else {
			if (logger.isTraceEnabled()) {
				logger.trace(LogMessage.format("Did not render default logout page since request did not match [%s]",
						this.matcher));
			}
			filterChain.doFilter(request, response);
		}
	}

	private void renderLogout(HttpServletRequest request, HttpServletResponse response) throws IOException {
		String renderedPage = HtmlTemplates.fromTemplate(LOGOUT_PAGE_TEMPLATE)
			.withValue("contextPath", request.getContextPath())
			.withRawHtml("hiddenInputs", renderHiddenInputs(request).indent(8))
			.render();
		response.setContentType("text/html;charset=UTF-8");
		response.getWriter().write(renderedPage);
	}

	/**
	 * Sets a Function used to resolve a Map of the hidden inputs where the key is the
	 * name of the input and the value is the value of the input. Typically this is used
	 * to resolve the CSRF token.
	 * @param resolveHiddenInputs the function to resolve the inputs
	 */
	public void setResolveHiddenInputs(Function<HttpServletRequest, Map<String, String>> resolveHiddenInputs) {
		Assert.notNull(resolveHiddenInputs, "resolveHiddenInputs cannot be null");
		this.resolveHiddenInputs = resolveHiddenInputs;
	}

	private String renderHiddenInputs(HttpServletRequest request) {
		StringBuilder sb = new StringBuilder();
		for (Map.Entry<String, String> input : this.resolveHiddenInputs.apply(request).entrySet()) {
			String inputElement = HtmlTemplates.fromTemplate(HIDDEN_HTML_INPUT_TEMPLATE)
				.withValue("name", input.getKey())
				.withValue("value", input.getValue())
				.render();
			sb.append(inputElement);
		}
		return sb.toString();
	}

	private static final String LOGOUT_PAGE_TEMPLATE = """
			<!DOCTYPE html>
			<html lang="en">
			  <head>
			    <meta charset="utf-8">
			    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
			    <meta name="description" content="">
			    <meta name="author" content="">
			    <title>Confirm Log Out?</title>
			    <link href="{{contextPath}}/default-ui.css" rel="stylesheet" />
			  </head>
			  <body>
			    <div class="content">
			      <form class="logout-form" method="post" action="{{contextPath}}/logout">
			        <h2>Are you sure you want to log out?</h2>
			{{hiddenInputs}}
			        <button class="primary" type="submit">Log Out</button>
			      </form>
			    </div>
			  </body>
			</html>""";

	private static final String HIDDEN_HTML_INPUT_TEMPLATE = """
			<input name="{{name}}" type="hidden" value="{{value}}" />
			""";

}
