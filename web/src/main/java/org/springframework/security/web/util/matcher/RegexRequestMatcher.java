/*
 * Copyright 2002-2016 the original author or authors.
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
package org.springframework.security.web.util.matcher;

import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.http.HttpMethod;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;

/**
 * Uses a regular expression to decide whether a supplied the URL of a supplied
 * {@code HttpServletRequest}.
 *
 * Can also be configured to match a specific HTTP method.
 *
 * The match is performed against the {@code servletPath + pathInfo + queryString} of the
 * request and is case-sensitive by default. Case-insensitive matching can be used by
 * using the constructor which takes the {@code caseInsensitive} argument.
 *
 * @author Luke Taylor
 * @author Rob Winch
 * @since 3.1
 */
public final class RegexRequestMatcher implements RequestMatcher {
	private final static Log logger = LogFactory.getLog(RegexRequestMatcher.class);

	private final Pattern pattern;
	private final HttpMethod httpMethod;

	/**
	 * Creates a case-sensitive {@code Pattern} instance to match against the request.
	 *
	 * @param pattern the regular expression to compile into a pattern.
	 * @param httpMethod the HTTP method to match. May be null to match all methods.
	 */
	public RegexRequestMatcher(String pattern, String httpMethod) {
		this(pattern, httpMethod, false);
	}

	/**
	 * As above, but allows setting of whether case-insensitive matching should be used.
	 *
	 * @param pattern the regular expression to compile into a pattern.
	 * @param httpMethod the HTTP method to match. May be null to match all methods.
	 * @param caseInsensitive if true, the pattern will be compiled with the
	 * {@link Pattern#CASE_INSENSITIVE} flag set.
	 */
	public RegexRequestMatcher(String pattern, String httpMethod, boolean caseInsensitive) {
		if (caseInsensitive) {
			this.pattern = Pattern.compile(pattern, Pattern.CASE_INSENSITIVE);
		}
		else {
			this.pattern = Pattern.compile(pattern);
		}
		this.httpMethod = StringUtils.hasText(httpMethod) ? HttpMethod
				.valueOf(httpMethod) : null;
	}

	/**
	 * Performs the match of the request URL ({@code servletPath + pathInfo + queryString}
	 * ) against the compiled pattern. If the query string is present, a question mark
	 * will be prepended.
	 *
	 * @param request the request to match
	 * @return true if the pattern matches the URL, false otherwise.
	 */
	public boolean matches(HttpServletRequest request) {
		if (httpMethod != null && request.getMethod() != null
				&& httpMethod != valueOf(request.getMethod())) {
			return false;
		}

		String url = request.getServletPath();
		String pathInfo = request.getPathInfo();
		String query = request.getQueryString();

		if (pathInfo != null || query != null) {
			StringBuilder sb = new StringBuilder(url);

			if (pathInfo != null) {
				sb.append(pathInfo);
			}

			if (query != null) {
				sb.append('?').append(query);
			}
			url = sb.toString();
		}

		if (logger.isDebugEnabled()) {
			logger.debug("Checking match of request : '" + url + "'; against '" + pattern
					+ "'");
		}

		return pattern.matcher(url).matches();
	}

	/**
	 * Provides a save way of obtaining the HttpMethod from a String. If the method is
	 * invalid, returns null.
	 *
	 * @param method the HTTP method to use.
	 *
	 * @return the HttpMethod or null if method is invalid.
	 */
	private static HttpMethod valueOf(String method) {
		try {
			return HttpMethod.valueOf(method);
		}
		catch (IllegalArgumentException e) {
		}

		return null;
	}
}
