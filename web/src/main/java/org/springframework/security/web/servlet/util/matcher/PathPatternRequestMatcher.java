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

import org.springframework.http.server.PathContainer;
import org.springframework.http.server.RequestPath;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatchers;
import org.springframework.web.util.ServletRequestPathUtils;
import org.springframework.web.util.pattern.PathPattern;
import org.springframework.web.util.pattern.PathPatternParser;

/**
 * A {@link RequestMatcher} that uses {@link PathPattern}s to match against each
 * {@link HttpServletRequest}. The provided path should be relative to the servlet (that
 * is, it should exclude any context or servlet path).
 *
 * <p>
 * To also match the servlet, please see {@link RequestMatchers#servlet}
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

	private final PathPattern pattern;

	/**
	 * Creates a {@link PathPatternRequestMatcher} that uses the provided {@code pattern}.
	 * <p>
	 * The {@code pattern} should be relative to the servlet path
	 * </p>
	 * @param pattern the pattern used to match
	 */
	public PathPatternRequestMatcher(PathPattern pattern) {
		this.pattern = pattern;
	}

	/**
	 * Creates a {@link PathPatternRequestMatcher} that uses the provided {@code pattern},
	 * parsing it with {@link PathPatternParser#defaultInstance}.
	 * <p>
	 * The {@code pattern} should be relative to the servlet path
	 * </p>
	 * @param pattern the pattern used to match
	 */
	public static PathPatternRequestMatcher pathPattern(String pattern) {
		PathPatternParser parser = PathPatternParser.defaultInstance;
		PathPattern pathPattern = parser.parse(pattern);
		return new PathPatternRequestMatcher(pathPattern);
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
		PathContainer path = getRequestPath(request).pathWithinApplication();
		PathPattern.PathMatchInfo info = this.pattern.matchAndExtract(path);
		return (info != null) ? MatchResult.match(info.getUriVariables()) : MatchResult.notMatch();
	}

	private RequestPath getRequestPath(HttpServletRequest request) {
		return ServletRequestPathUtils.parseAndCache(request);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean equals(Object o) {
		if (!(o instanceof PathPatternRequestMatcher that)) {
			return false;
		}
		return Objects.equals(this.pattern, that.pattern);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public int hashCode() {
		return Objects.hash(this.pattern);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String toString() {
		return "PathPattern [" + this.pattern + "]";
	}

}
