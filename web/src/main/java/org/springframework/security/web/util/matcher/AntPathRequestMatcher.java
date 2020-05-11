/*
 * Copyright 2002-2018 the original author or authors.
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

import java.util.Collections;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.http.HttpMethod;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UrlPathHelper;

/**
 * Matcher which compares a pre-defined ant-style pattern against the URL (
 * {@code servletPath + pathInfo}) of an {@code HttpServletRequest}. The query string of
 * the URL is ignored and matching is case-insensitive or case-sensitive depending on the
 * arguments passed into the constructor.
 * <p>
 * Using a pattern value of {@code /**} or {@code **} is treated as a universal match,
 * which will match any request. Patterns which end with {@code /**} (and have no other
 * wildcards) are optimized by using a substring match &mdash; a pattern of
 * {@code /aaa/**} will match {@code /aaa}, {@code /aaa/} and any sub-directories, such as
 * {@code /aaa/bbb/ccc}.
 * </p>
 * <p>
 * For all other cases, Spring's {@link AntPathMatcher} is used to perform the match. See
 * the Spring documentation for this class for comprehensive information on the syntax
 * used.
 * </p>
 *
 * @author Luke Taylor
 * @author Rob Winch
 * @since 3.1
 *
 * @see org.springframework.util.AntPathMatcher
 */
public final class AntPathRequestMatcher
		implements RequestMatcher, RequestVariablesExtractor {
	private static final Log logger = LogFactory.getLog(AntPathRequestMatcher.class);
	private static final String MATCH_ALL = "/**";

	private final Matcher matcher;
	private final String pattern;
	private final HttpMethod httpMethod;
	private final boolean caseSensitive;

	private final UrlPathHelper urlPathHelper;

	/**
	 * Creates a matcher with the specific pattern which will match all HTTP methods in a
	 * case sensitive manner.
	 *
	 * @param pattern the ant pattern to use for matching
	 */
	public AntPathRequestMatcher(String pattern) {
		this(pattern, null);
	}

	/**
	 * Creates a matcher with the supplied pattern and HTTP method in a case sensitive
	 * manner.
	 *
	 * @param pattern the ant pattern to use for matching
	 * @param httpMethod the HTTP method. The {@code matches} method will return false if
	 * the incoming request doesn't have the same method.
	 */
	public AntPathRequestMatcher(String pattern, String httpMethod) {
		this(pattern, httpMethod, true);
	}

	/**
	 * Creates a matcher with the supplied pattern which will match the specified Http
	 * method
	 *
	 * @param pattern the ant pattern to use for matching
	 * @param httpMethod the HTTP method. The {@code matches} method will return false if
	 * the incoming request doesn't doesn't have the same method.
	 * @param caseSensitive true if the matcher should consider case, else false
	 */
	public AntPathRequestMatcher(String pattern, String httpMethod,
			boolean caseSensitive) {
		this(pattern, httpMethod, caseSensitive, null);
	}

	/**
	 * Creates a matcher with the supplied pattern which will match the specified Http
	 * method
	 *
	 * @param pattern the ant pattern to use for matching
	 * @param httpMethod the HTTP method. The {@code matches} method will return false if
	 * the incoming request doesn't have the same method.
	 * @param caseSensitive true if the matcher should consider case, else false
	 * @param urlPathHelper if non-null, will be used for extracting the path from the HttpServletRequest
	 */
	public AntPathRequestMatcher(String pattern, String httpMethod,
			boolean caseSensitive, UrlPathHelper urlPathHelper) {
		Assert.hasText(pattern, "Pattern cannot be null or empty");
		this.caseSensitive = caseSensitive;

		if (pattern.equals(MATCH_ALL) || pattern.equals("**")) {
			pattern = MATCH_ALL;
			this.matcher = null;
		}
		else {
			// If the pattern ends with {@code /**} and has no other wildcards or path
			// variables, then optimize to a sub-path match
			if (pattern.endsWith(MATCH_ALL)
					&& (pattern.indexOf('?') == -1 && pattern.indexOf('{') == -1
							&& pattern.indexOf('}') == -1)
					&& pattern.indexOf("*") == pattern.length() - 2) {
				this.matcher = new SubpathMatcher(
						pattern.substring(0, pattern.length() - 3), caseSensitive);
			}
			else {
				this.matcher = new SpringAntMatcher(pattern, caseSensitive);
			}
		}

		this.pattern = pattern;
		this.httpMethod = StringUtils.hasText(httpMethod) ? HttpMethod.valueOf(httpMethod)
				: null;
		this.urlPathHelper = urlPathHelper;
	}

	/**
	 * Returns true if the configured pattern (and HTTP-Method) match those of the
	 * supplied request.
	 *
	 * @param request the request to match against. The ant pattern will be matched
	 * against the {@code servletPath} + {@code pathInfo} of the request.
	 */
	@Override
	public boolean matches(HttpServletRequest request) {
		if (this.httpMethod != null && StringUtils.hasText(request.getMethod())
				&& this.httpMethod != valueOf(request.getMethod())) {
			if (logger.isDebugEnabled()) {
				logger.debug("Request '" + request.getMethod() + " "
						+ getRequestPath(request) + "'" + " doesn't match '"
						+ this.httpMethod + " " + this.pattern + "'");
			}

			return false;
		}

		if (this.pattern.equals(MATCH_ALL)) {
			if (logger.isDebugEnabled()) {
				logger.debug("Request '" + getRequestPath(request)
						+ "' matched by universal pattern '/**'");
			}

			return true;
		}

		String url = getRequestPath(request);

		if (logger.isDebugEnabled()) {
			logger.debug("Checking match of request : '" + url + "'; against '"
					+ this.pattern + "'");
		}

		return this.matcher.matches(url);
	}

	@Override
	public Map<String, String> extractUriTemplateVariables(HttpServletRequest request) {
		if (this.matcher == null || !matches(request)) {
			return Collections.emptyMap();
		}
		String url = getRequestPath(request);
		return this.matcher.extractUriTemplateVariables(url);
	}

	private String getRequestPath(HttpServletRequest request) {
		if (this.urlPathHelper != null) {
			return this.urlPathHelper.getPathWithinApplication(request);
		}
		String url = request.getServletPath();

		String pathInfo = request.getPathInfo();
		if (pathInfo != null) {
			url = StringUtils.hasLength(url) ? url + pathInfo : pathInfo;
		}

		return url;
	}

	public String getPattern() {
		return this.pattern;
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof AntPathRequestMatcher)) {
			return false;
		}

		AntPathRequestMatcher other = (AntPathRequestMatcher) obj;
		return this.pattern.equals(other.pattern) && this.httpMethod == other.httpMethod
				&& this.caseSensitive == other.caseSensitive;
	}

	@Override
	public int hashCode() {
		int code = 31 ^ this.pattern.hashCode();
		if (this.httpMethod != null) {
			code ^= this.httpMethod.hashCode();
		}
		return code;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("Ant [pattern='").append(this.pattern).append("'");

		if (this.httpMethod != null) {
			sb.append(", ").append(this.httpMethod);
		}

		sb.append("]");

		return sb.toString();
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

	private static interface Matcher {
		boolean matches(String path);

		Map<String, String> extractUriTemplateVariables(String path);
	}

	private static class SpringAntMatcher implements Matcher {
		private final AntPathMatcher antMatcher;

		private final String pattern;

		private SpringAntMatcher(String pattern, boolean caseSensitive) {
			this.pattern = pattern;
			this.antMatcher = createMatcher(caseSensitive);
		}

		@Override
		public boolean matches(String path) {
			return this.antMatcher.match(this.pattern, path);
		}

		@Override
		public Map<String, String> extractUriTemplateVariables(String path) {
			return this.antMatcher.extractUriTemplateVariables(this.pattern, path);
		}

		private static AntPathMatcher createMatcher(boolean caseSensitive) {
			AntPathMatcher matcher = new AntPathMatcher();
			matcher.setTrimTokens(false);
			matcher.setCaseSensitive(caseSensitive);
			return matcher;
		}
	}

	/**
	 * Optimized matcher for trailing wildcards
	 */
	private static class SubpathMatcher implements Matcher {
		private final String subpath;
		private final int length;
		private final boolean caseSensitive;

		private SubpathMatcher(String subpath, boolean caseSensitive) {
			assert!subpath.contains("*");
			this.subpath = caseSensitive ? subpath : subpath.toLowerCase();
			this.length = subpath.length();
			this.caseSensitive = caseSensitive;
		}

		@Override
		public boolean matches(String path) {
			if (!this.caseSensitive) {
				path = path.toLowerCase();
			}
			return path.startsWith(this.subpath)
					&& (path.length() == this.length || path.charAt(this.length) == '/');
		}

		@Override
		public Map<String, String> extractUriTemplateVariables(String path) {
			return Collections.emptyMap();
		}
	}
}
