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

package org.springframework.security.web.servlet.util.matcher;

import java.util.Objects;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.http.HttpMethod;
import org.springframework.http.server.PathContainer;
import org.springframework.http.server.RequestPath;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.util.WebUtils;
import org.springframework.web.util.pattern.PathPattern;
import org.springframework.web.util.pattern.PathPatternParser;

/**
 * A {@link RequestMatcher} that uses {@link PathPattern}s to match against each
 * {@link HttpServletRequest}. Specifically, this means that the class anticipates that
 * the provided pattern does not include the servlet path in order to align with Spring
 * MVC.
 *
 * <p>
 * Note that the {@link org.springframework.web.servlet.HandlerMapping} that contains the
 * related URI patterns must be using the same
 * {@link org.springframework.web.util.pattern.PathPatternParser} configured in this
 * class.
 * </p>
 *
 * @author Josh Cummings
 * @since 6.5
 */
public final class PathPatternRequestMatcher implements RequestMatcher {

	private final HttpMethod method;

	private final PathPattern pattern;

	/**
	 * Creates an {@link PathPatternRequestMatcher} that uses the provided
	 * {@code pattern}.
	 * <p>
	 * The {@code pattern} should be absolute (less the context path)
	 * </p>
	 * @param pattern the pattern used to match
	 */
	public PathPatternRequestMatcher(PathPattern pattern) {
		this(null, pattern);
	}

	/**
	 * Creates an {@link PathPatternRequestMatcher} that uses the provided {@code pattern}
	 * and HTTP {@code method} to match.
	 * <p>
	 * The {@code pattern} should be absolute (less the context path)
	 * </p>
	 * @param method the {@link HttpMethod}, can be null
	 * @param pattern the pattern used to match; if a path, must be relative to its
	 * servlet path
	 */
	public PathPatternRequestMatcher(HttpMethod method, PathPattern pattern) {
		this.method = method;
		this.pattern = pattern;
	}

	/**
	 * Creates an {@link PathPatternRequestMatcher} that uses the provided {@code pattern}
	 * and HTTP {@code method} to match.
	 * <p>
	 * The {@code pattern} should be absolute (less the context path)
	 * </p>
	 * @param method the {@link HttpMethod}, can be null
	 * @param pattern the pattern used to match; if a path, must be relative to its
	 * servlet path
	 * @return the generated {@link PathPatternRequestMatcher}
	 */
	public static PathPatternRequestMatcher pathPattern(HttpMethod method, String pattern) {
		Assert.notNull(pattern, "pattern cannot be null");
		Assert.isTrue(pattern.startsWith("/"), "pattern must start with '/'");
		PathPatternParser parser = PathPatternParser.defaultInstance;
		String parsed = parser.initFullPathPattern(pattern);
		PathPattern pathPattern = parser.parse(parsed);
		return new PathPatternRequestMatcher(method, pathPattern);
	}

	/**
	 * Creates an {@link PathPatternRequestMatcher} that uses the provided
	 * {@code pattern}.
	 * <p>
	 * The {@code pattern} should be absolute (less the context path)
	 * </p>
	 * @param pattern the pattern used to match
	 * @return the generated {@link PathPatternRequestMatcher}
	 */
	public static PathPatternRequestMatcher pathPattern(String pattern) {
		return pathPattern(null, pattern);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean matches(HttpServletRequest request) {
		return matcher(request).isMatch();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public MatchResult matcher(HttpServletRequest request) {
		if (this.method != null && !this.method.name().equals(request.getMethod())) {
			return MatchResult.notMatch();
		}
		PathContainer path = getRequestPath(request).pathWithinApplication();
		PathPattern.PathMatchInfo info = this.pattern.matchAndExtract(path);
		return (info != null) ? MatchResult.match(info.getUriVariables()) : MatchResult.notMatch();
	}

	private RequestPath getRequestPath(HttpServletRequest request) {
		String requestUri = (String) request.getAttribute(WebUtils.INCLUDE_REQUEST_URI_ATTRIBUTE);
		requestUri = (requestUri != null) ? requestUri : request.getRequestURI();
		return RequestPath.parse(requestUri, request.getContextPath());
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean equals(Object o) {
		if (!(o instanceof PathPatternRequestMatcher that)) {
			return false;
		}
		return Objects.equals(this.method, that.method) && Objects.equals(this.pattern, that.pattern);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public int hashCode() {
		return Objects.hash(this.method, this.pattern);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String toString() {
		return "PathPatternRequestMatcher [method=" + this.method + ", pattern=" + this.pattern + "]";
	}

}
