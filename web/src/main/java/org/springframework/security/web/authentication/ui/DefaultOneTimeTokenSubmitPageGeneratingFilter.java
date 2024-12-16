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
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Creates a default one-time token submit page. If the request contains a {@code token}
 * query param the page will automatically fill the form with the token value.
 *
 * @author Marcus da Coregio
 * @since 6.4
 */
public final class DefaultOneTimeTokenSubmitPageGeneratingFilter extends OncePerRequestFilter {

	private RequestMatcher requestMatcher = new AntPathRequestMatcher("/login/ott", "GET");

	private Function<HttpServletRequest, Map<String, String>> resolveHiddenInputs = (request) -> Collections.emptyMap();

	private String loginProcessingUrl = "/login/ott";

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		if (!this.requestMatcher.matches(request)) {
			filterChain.doFilter(request, response);
			return;
		}
		String html = generateHtml(request);
		response.setContentType("text/html;charset=UTF-8");
		response.setContentLength(html.getBytes(StandardCharsets.UTF_8).length);
		response.getWriter().write(html);
	}

	private String generateHtml(HttpServletRequest request) {
		String contextPath = request.getContextPath();

		String token = request.getParameter("token");
		String tokenValue = StringUtils.hasText(token) ? token : "";

		String hiddenInputs = this.resolveHiddenInputs.apply(request)
			.entrySet()
			.stream()
			.map((inputKeyValue) -> renderHiddenInput(inputKeyValue.getKey(), inputKeyValue.getValue()))
			.collect(Collectors.joining("\n"));

		return HtmlTemplates.fromTemplate(ONE_TIME_TOKEN_SUBMIT_PAGE_TEMPLATE)
			.withValue("contextPath", contextPath)
			.withValue("tokenValue", tokenValue)
			.withValue("loginProcessingUrl", contextPath + this.loginProcessingUrl)
			.withRawHtml("hiddenInputs", hiddenInputs)
			.render();
	}

	private String renderHiddenInput(String name, String value) {
		return HtmlTemplates.fromTemplate(HIDDEN_HTML_INPUT_TEMPLATE)
			.withValue("name", name)
			.withValue("value", value)
			.render();
	}

	/**
	 * Sets a Function used to resolve a Map of the hidden inputs where the key is the
	 * name of the input and the value is the value of the input.
	 * @param resolveHiddenInputs the function to resolve the inputs
	 */
	public void setResolveHiddenInputs(Function<HttpServletRequest, Map<String, String>> resolveHiddenInputs) {
		Assert.notNull(resolveHiddenInputs, "resolveHiddenInputs cannot be null");
		this.resolveHiddenInputs = resolveHiddenInputs;
	}

	/**
	 * Use this {@link RequestMatcher} to choose whether this filter will handle the
	 * request. By default, it handles {@code /login/ott}.
	 * @param requestMatcher the {@link RequestMatcher} to use
	 */
	public void setRequestMatcher(RequestMatcher requestMatcher) {
		Assert.notNull(requestMatcher, "requestMatcher cannot be null");
		this.requestMatcher = requestMatcher;
	}

	/**
	 * Specifies the URL that the submit form should POST to. Defaults to
	 * {@code /login/ott}.
	 * @param loginProcessingUrl
	 */
	public void setLoginProcessingUrl(String loginProcessingUrl) {
		Assert.hasText(loginProcessingUrl, "loginProcessingUrl cannot be null or empty");
		this.loginProcessingUrl = loginProcessingUrl;
	}

	private static final String ONE_TIME_TOKEN_SUBMIT_PAGE_TEMPLATE = """
			<!DOCTYPE html>
			<html lang="en">
			  <head>
			    <title>One-Time Token Login</title>
			    <meta charset="utf-8"/>
			    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no"/>
			    <link href="{{contextPath}}/default-ui.css" rel="stylesheet" />
			  </head>
			  <body>
			    <div class="container">
			      <form class="login-form" action="{{loginProcessingUrl}}" method="post">
			        <h2>Please input the token</h2>
			        <p>
			          <label for="token" class="screenreader">Token</label>
			          <input type="text" id="token" name="token" value="{{tokenValue}}" placeholder="Token" required="true" autofocus="autofocus"/>
			        </p>
			        <button class="primary" type="submit">Sign in</button>
			{{hiddenInputs}}
			      </form>
			    </div>
			  </body>
			</html>
			""";

	private static final String HIDDEN_HTML_INPUT_TEMPLATE = """
			<input name="{{name}}" type="hidden" value="{{value}}" />
			""";

}
