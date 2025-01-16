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
import org.springframework.security.web.util.matcher.RequestMatcherBuilder;
import org.springframework.util.Assert;
import org.springframework.web.util.ServletRequestPathUtils;
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

	private static final String PATH_ATTRIBUTE = PathPatternRequestMatcher.class + ".PATH";

	static final String ANY_SERVLET = new String();

	private final PathPattern pattern;

	private String servletPath;

	private HttpMethod method;

	PathPatternRequestMatcher(PathPattern pattern) {
		this.pattern = pattern;
	}

	/**
	 * Create a {@link Builder} for creating {@link PathPattern}-based request matchers.
	 * That is, matchers that anticipate patterns do not specify the servlet path.
	 * @return the {@link Builder}
	 */
	public static Builder builder() {
		return new Builder(PathPatternParser.defaultInstance);
	}

	/**
	 * Create a {@link Builder} for creating {@link PathPattern}-based request matchers.
	 * That is, matchers that anticipate patterns do not specify the servlet path.
	 * @param parser the {@link PathPatternParser}; only needed when different from
	 * {@link PathPatternParser#defaultInstance}
	 * @return the {@link Builder}
	 */
	public static Builder withPathPatternParser(PathPatternParser parser) {
		return new Builder(parser);
	}

	@Override
	public boolean matches(HttpServletRequest request) {
		return matcher(request).isMatch();
	}

	@Override
	public MatchResult matcher(HttpServletRequest request) {
		if (this.method != null && !this.method.name().equals(request.getMethod())) {
			return MatchResult.notMatch();
		}
		if (this.servletPath != null && !this.servletPath.equals(request.getServletPath())
				&& !ANY_SERVLET.equals(this.servletPath)) {
			return MatchResult.notMatch();
		}
		PathContainer path = getPathContainer(request);
		PathPattern.PathMatchInfo info = this.pattern.matchAndExtract(path);
		return (info != null) ? MatchResult.match(info.getUriVariables()) : MatchResult.notMatch();
	}

	PathContainer getPathContainer(HttpServletRequest request) {
		if (this.servletPath != null) {
			return ServletRequestPathUtils.parseAndCache(request).pathWithinApplication();
		}
		else {
			return parseAndCache(request);
		}
	}

	PathContainer parseAndCache(HttpServletRequest request) {
		PathContainer path = (PathContainer) request.getAttribute(PATH_ATTRIBUTE);
		if (path != null) {
			return path;
		}
		path = RequestPath.parse(request.getRequestURI(), request.getContextPath()).pathWithinApplication();
		request.setAttribute(PATH_ATTRIBUTE, path);
		return path;
	}

	void setServletPath(String servletPath) {
		this.servletPath = servletPath;
	}

	void setMethod(HttpMethod method) {
		this.method = method;
	}

	@Override
	public boolean equals(Object o) {
		if (!(o instanceof PathPatternRequestMatcher that)) {
			return false;
		}
		return Objects.equals(this.pattern, that.pattern) && Objects.equals(this.servletPath, that.servletPath)
				&& Objects.equals(this.method, that.method);
	}

	@Override
	public int hashCode() {
		return Objects.hash(this.pattern, this.servletPath, this.method);
	}

	@Override
	public String toString() {
		return "PathPatternRequestMatcher [pattern=" + this.pattern + ", servletPath=" + this.servletPath + ", method="
				+ this.method + ']';
	}

	/**
	 * A builder for {@link MvcRequestMatcher}
	 *
	 * @author Marcus Da Coregio
	 * @since 6.5
	 */
	public static final class Builder implements RequestMatcherBuilder {

		private final PathPatternParser parser;

		private HttpMethod method;

		private String servletPath;

		/**
		 * Construct a new instance of this builder
		 */
		public Builder(PathPatternParser parser) {
			Assert.notNull(parser, "pathPatternParser cannot be null");
			this.parser = parser;
		}

		public Builder method(HttpMethod method) {
			this.method = method;
			return this;
		}

		/**
		 * Sets the servlet path to be used by the {@link MvcRequestMatcher} generated by
		 * this builder
		 * @param servletPath the servlet path to use
		 * @return the {@link MvcRequestMatcher.Builder} for further configuration
		 */
		public Builder servletPath(String servletPath) {
			this.servletPath = servletPath;
			return this;
		}

		/**
		 * Creates an {@link MvcRequestMatcher} that uses the provided pattern and HTTP
		 * method to match
		 * @param method the {@link HttpMethod}, can be null
		 * @param pattern the patterns used to match
		 * @return the generated {@link MvcRequestMatcher}
		 */
		public PathPatternRequestMatcher pattern(HttpMethod method, String pattern) {
			String parsed = this.parser.initFullPathPattern(pattern);
			PathPattern pathPattern = this.parser.parse(parsed);
			PathPatternRequestMatcher requestMatcher = new PathPatternRequestMatcher(pathPattern);
			requestMatcher.setServletPath(this.servletPath);
			requestMatcher.setMethod(method);
			return requestMatcher;
		}

	}

}
