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
import org.springframework.lang.Nullable;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.util.ServletRequestPathUtils;
import org.springframework.web.util.pattern.PathPattern;
import org.springframework.web.util.pattern.PathPatternParser;

/**
 * A {@link RequestMatcher} that uses {@link PathPattern}s to match against each
 * {@link HttpServletRequest}. The provided path should be relative to the context path
 * (that is, it should exclude any context path).
 *
 * <p>
 * You can provide the servlet path in {@link PathPatternRequestMatcher#servletPath} and
 * reuse for multiple matchers.
 *
 * <p>
 * Note that the {@link org.springframework.web.servlet.HandlerMapping} that contains the
 * related URI patterns must be using {@link PathPatternParser#defaultInstance}. If that
 * is not the case, use {@link PathPatternParser} to parse your path and provide a
 * {@link PathPattern} in the constructor.
 * </p>
 *
 * @author Josh Cummings
 * @since 6.5
 */
public final class PathPatternRequestMatcher implements RequestMatcher {

	private final PathPattern pattern;

	private RequestMatcher servletPath = AnyRequestMatcher.INSTANCE;

	private RequestMatcher method = AnyRequestMatcher.INSTANCE;

	/**
	 * Creates a {@link PathPatternRequestMatcher} that uses the provided {@code pattern}.
	 * <p>
	 * The {@code pattern} should be relative to the servlet path
	 * </p>
	 * @param pattern the pattern used to match
	 */
	private PathPatternRequestMatcher(PathPattern pattern) {
		this.pattern = pattern;
	}

	/**
	 * Construct a {@link PathPatternRequestMatcher} using the {@link PathPatternParser}
	 * defaults.
	 * <p>
	 * If you are configuring a custom {@link PathPatternParser}, please use
	 * {@link #withPathPatternParser} instead.
	 * @param pattern the URI pattern to match
	 * @return a {@link PathPatternRequestMatcher} that matches requests to the given
	 * {@code pattern}
	 * @since 7.0
	 * @see PathPattern
	 */
	public static PathPatternRequestMatcher pathPattern(String pattern) {
		return pathPattern(null, pattern);
	}

	/**
	 * Construct a {@link PathPatternRequestMatcher} using the {@link PathPatternParser}
	 * defaults.
	 * <p>
	 * If you are configuring a custom {@link PathPatternParser}, please use
	 * {@link #withPathPatternParser} instead.
	 * @param method the HTTP method to match, {@code null} indicates that the method does
	 * not matter
	 * @param pattern the URI pattern to match
	 * @return a {@link PathPatternRequestMatcher} that matches requests to the given
	 * {@code pattern} and {@code method}
	 * @since 7.0
	 * @see PathPattern
	 */
	public static PathPatternRequestMatcher pathPattern(@Nullable HttpMethod method, String pattern) {
		return withDefaults().matcher(method, pattern);
	}

	/**
	 * Use {@link PathPatternParser#defaultInstance} to parse path patterns.
	 * @return a {@link Builder} that treats URIs as relative to the context path, if any
	 */
	public static Builder withDefaults() {
		return new Builder();
	}

	/**
	 * Use this {@link PathPatternParser} to parse path patterns.
	 * @param parser the {@link PathPatternParser} to use
	 * @return a {@link Builder} that treats URIs as relative to the given
	 * {@code servletPath}
	 */
	public static Builder withPathPatternParser(PathPatternParser parser) {
		Assert.notNull(parser, "pathPatternParser cannot be null");
		return new Builder(parser);
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
		if (!this.servletPath.matches(request)) {
			return MatchResult.notMatch();
		}
		if (!this.method.matches(request)) {
			return MatchResult.notMatch();
		}
		PathContainer path = getPathContainer(request);
		PathPattern.PathMatchInfo info = this.pattern.matchAndExtract(path);
		return (info != null) ? MatchResult.match(info.getUriVariables()) : MatchResult.notMatch();
	}

	void setMethod(RequestMatcher method) {
		this.method = method;
	}

	private PathContainer getPathContainer(HttpServletRequest request) {
		RequestPath path;
		if (ServletRequestPathUtils.hasParsedRequestPath(request)) {
			path = ServletRequestPathUtils.getParsedRequestPath(request);
		}
		else {
			path = ServletRequestPathUtils.parseAndCache(request);
			ServletRequestPathUtils.clearParsedRequestPath(request);
		}
		PathContainer contextPath = path.contextPath();
		return path.subPath(contextPath.elements().size());
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean equals(Object o) {
		if (!(o instanceof PathPatternRequestMatcher that)) {
			return false;
		}
		return Objects.equals(this.pattern, that.pattern) && Objects.equals(this.method, that.method);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public int hashCode() {
		return Objects.hash(this.pattern, this.method);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String toString() {
		StringBuilder request = new StringBuilder();
		if (this.method instanceof HttpMethodRequestMatcher m) {
			request.append(m.method.name()).append(' ');
		}
		return "PathPattern [" + request + this.pattern + "]";
	}

	/**
	 * A builder for specifying various elements of a request for the purpose of creating
	 * a {@link PathPatternRequestMatcher}.
	 *
	 * <p>
	 * To match a request URI like {@code /app/servlet/my/resource/**} where {@code /app}
	 * is the context path, you can do
	 * {@code PathPatternRequestMatcher.withDefaults().matcher("/servlet/my/resource/**")}
	 *
	 * <p>
	 * If you have many paths that have a common path prefix, you can use
	 * {@link #basePath} to reduce repetition like so:
	 *
	 * <pre>
	 *     PathPatternRequestMatcher.Builder mvc = withDefaults().basePath("/mvc");
	 *     http
	 *         .authorizeHttpRequests((authorize) -> authorize
	 *              .requestMatchers(mvc.matcher("/user/**")).hasAuthority("user")
	 *              .requestMatchers(mvc.matcher("/admin/**")).hasAuthority("admin")
	 *         )
	 *             ...
	 * </pre>
	 */
	public static final class Builder {

		private final PathPatternParser parser;

		private final String basePath;

		Builder() {
			this(PathPatternParser.defaultInstance);
		}

		Builder(PathPatternParser parser) {
			this(parser, "");
		}

		Builder(PathPatternParser parser, String basePath) {
			this.parser = parser;
			this.basePath = basePath;
		}

		/**
		 * Match requests starting with this {@code basePath}.
		 *
		 * <p>
		 * Prefixes should be of the form {@code /my/prefix}, starting with a slash, not
		 * ending in a slash, and not containing and wildcards
		 * @param basePath the path prefix
		 * @return the {@link Builder} for more configuration
		 */
		public Builder basePath(String basePath) {
			Assert.notNull(basePath, "basePath cannot be null");
			Assert.isTrue(basePath.startsWith("/"), "basePath must start with '/'");
			Assert.isTrue(!basePath.endsWith("/"), "basePath must not end with a slash");
			Assert.isTrue(!basePath.contains("*"), "basePath must not contain a star");
			return new Builder(this.parser, basePath);
		}

		/**
		 * Match requests having this path pattern.
		 *
		 * <p>
		 * When the HTTP {@code method} is null, then the matcher does not consider the
		 * HTTP method
		 *
		 * <p>
		 * Path patterns always start with a slash and may contain placeholders. They can
		 * also be followed by {@code /**} to signify all URIs under a given path.
		 *
		 * <p>
		 * These must be specified relative to any servlet path prefix (meaning you should
		 * exclude the context path and any servlet path prefix in stating your pattern).
		 *
		 * <p>
		 * The following are valid patterns and their meaning
		 * <ul>
		 * <li>{@code /path} - match exactly and only `/path`</li>
		 * <li>{@code /path/**} - match `/path` and any of its descendents</li>
		 * <li>{@code /path/{value}/**} - match `/path/subdirectory` and any of its
		 * descendents, capturing the value of the subdirectory in
		 * {@link RequestAuthorizationContext#getVariables()}</li>
		 * </ul>
		 *
		 * <p>
		 * A more comprehensive list can be found at {@link PathPattern}.
		 * @param path the path pattern to match
		 * @return the {@link Builder} for more configuration
		 */
		public PathPatternRequestMatcher matcher(String path) {
			return matcher(null, path);
		}

		/**
		 * Match requests having this {@link HttpMethod} and path pattern.
		 *
		 * <p>
		 * When the HTTP {@code method} is null, then the matcher does not consider the
		 * HTTP method
		 *
		 * <p>
		 * Path patterns always start with a slash and may contain placeholders. They can
		 * also be followed by {@code /**} to signify all URIs under a given path.
		 *
		 * <p>
		 * These must be specified relative to any servlet path prefix (meaning you should
		 * exclude the context path and any servlet path prefix in stating your pattern).
		 *
		 * <p>
		 * The following are valid patterns and their meaning
		 * <ul>
		 * <li>{@code /path} - match exactly and only `/path`</li>
		 * <li>{@code /path/**} - match `/path` and any of its descendents</li>
		 * <li>{@code /path/{value}/**} - match `/path/subdirectory` and any of its
		 * descendents, capturing the value of the subdirectory in
		 * {@link RequestAuthorizationContext#getVariables()}</li>
		 * </ul>
		 *
		 * <p>
		 * A more comprehensive list can be found at {@link PathPattern}.
		 * @param method the {@link HttpMethod} to match, may be null
		 * @param path the path pattern to match
		 * @return the {@link Builder} for more configuration
		 */
		public PathPatternRequestMatcher matcher(@Nullable HttpMethod method, String path) {
			Assert.notNull(path, "pattern cannot be null");
			Assert.isTrue(path.startsWith("/"), "pattern must start with a /");
			PathPattern pathPattern = this.parser.parse(this.basePath + path);
			PathPatternRequestMatcher requestMatcher = new PathPatternRequestMatcher(pathPattern);
			if (method != null) {
				requestMatcher.setMethod(new HttpMethodRequestMatcher(method));
			}
			return requestMatcher;
		}

	}

	private static final class HttpMethodRequestMatcher implements RequestMatcher {

		private final HttpMethod method;

		HttpMethodRequestMatcher(HttpMethod method) {
			this.method = method;
		}

		@Override
		public boolean matches(HttpServletRequest request) {
			return this.method.name().equals(request.getMethod());
		}

		@Override
		public String toString() {
			return "HttpMethod [" + this.method + "]";
		}

	}

}
