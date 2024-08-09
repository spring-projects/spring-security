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
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.web.util.UrlUtils;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

public class DefaultOneTimeTokenConfirmationPageGeneratingFilter extends OncePerRequestFilter {

	private RequestMatcher requestMatcher = new AntPathRequestMatcher("/login/ott", "GET");

	private Function<HttpServletRequest, Map<String, String>> resolveHiddenInputs = (request) -> Collections.emptyMap();

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
		UriComponents uriComponents = UriComponentsBuilder.fromUriString(UrlUtils.buildFullRequestUrl(request)).build();
		List<String> tokens = uriComponents.getQueryParams().get("token");
		boolean autoSubmitForm = !CollectionUtils.isEmpty(tokens);
		String inputValue = autoSubmitForm ? tokens.get(0) : "";
		String input = "<input type=\"text\" id=\"token\" name=\"token\" value=\"" + inputValue
				+ "\" placeholder=\"Token\" class=\"form-control\" required autofocus=\"autofocus\"/>";
		return """
				<!DOCTYPE html>
				<html lang="en">
				<head>
					<title>Passwordless Login</title>
					<meta charset="utf-8"/>
					<meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
					<meta http-equiv="Content-Security-Policy" content="script-src 'sha256-oZhLbc2kO8b8oaYLrUc7uye1MgVKMyLtPqWR4WtKF+c='">
					<link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-beta/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-/Y6pD6FV/Vv2HJnA6t+vslU6fwYXjCFtcEpHbNJ0lyAFsXTsjBbfaDjzALeQsN6M" crossorigin="anonymous">
					<link href="https://getbootstrap.com/docs/4.0/examples/signin/signin.css" rel="stylesheet" integrity="sha384-oOE/3m0LUMPub4kaC09mrdEhIc+e3exm4xOGxAmuFXhBNF4hcg/6MiAXAf5p0P56" crossorigin="anonymous">
					<title>One Time Token Login</title>
				</head>
				<body>
					<noscript>
						<p>
							<strong>Note:</strong> Since your browser does not support JavaScript, you must press the Sign In button once to proceed.
						</p>
					</noscript>
					<div class="container">
						<form class="form-signin" action="/login/ott" method="post">
							<h2 class="form-signin-heading">Please input the token</h2>
							<p>
								<label for="token" class="sr-only">Token</label>
				"""
				+ input + """
									</p>
									<button class="btn btn-lg btn-primary btn-block" type="submit">Sign in</button>
						""" + renderHiddenInputs(request) + """
								</form>
							</div>
							<script>window.onload = function() { document.forms[0].submit(); }</script>
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

}
