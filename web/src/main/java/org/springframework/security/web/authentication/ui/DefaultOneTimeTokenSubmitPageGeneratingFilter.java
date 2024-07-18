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

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.web.util.CssUtils;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.HtmlUtils;

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
		String token = request.getParameter("token");
		String inputValue = StringUtils.hasText(token) ? HtmlUtils.htmlEscape(token) : "";
		String input = "<input type=\"text\" id=\"token\" name=\"token\" value=\"" + inputValue + "\""
				+ " placeholder=\"Token\" required=\"true\" autofocus=\"autofocus\"/>";
		return """
				<!DOCTYPE html>
				<html lang="en">
				<head>
					<title>One-Time Token Login</title>
					<meta charset="utf-8"/>
					<meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no"/>
					<meta http-equiv="Content-Security-Policy" content="script-src 'sha256-oZhLbc2kO8b8oaYLrUc7uye1MgVKMyLtPqWR4WtKF+c='"/>
				"""
				+ CssUtils.getCssStyleBlock().indent(4)
				+ """
						</head>
						<body>
							<noscript>
								<p>
									<strong>Note:</strong> Since your browser does not support JavaScript, you must press the Sign In button once to proceed.
								</p>
							</noscript>
							<div class="container">
						"""
				+ "<form class=\"login-form\" action=\"" + this.loginProcessingUrl + "\" method=\"post\">" + """
							<h2>Please input the token</h2>
							<p>
								<label for="token" class="screenreader">Token</label>
						""" + input + """
								</p>
								<button class="primary" type="submit">Sign in</button>
						""" + renderHiddenInputs(request) + """
							</form>
						</div>
						</body>
						</html>
						""";
	}

	private String renderHiddenInputs(HttpServletRequest request) {
		StringBuilder sb = new StringBuilder();
		for (Map.Entry<String, String> input : this.resolveHiddenInputs.apply(request).entrySet()) {
			sb.append("<input name=\"");
			sb.append(input.getKey());
			sb.append("\" type=\"hidden\" value=\"");
			sb.append(input.getValue());
			sb.append("\" />\n");
		}
		return sb.toString();
	}

	public void setResolveHiddenInputs(Function<HttpServletRequest, Map<String, String>> resolveHiddenInputs) {
		Assert.notNull(resolveHiddenInputs, "resolveHiddenInputs cannot be null");
		this.resolveHiddenInputs = resolveHiddenInputs;
	}

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

}
