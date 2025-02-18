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

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletRegistration;
import jakarta.servlet.http.HttpServletRequest;

import org.springframework.http.HttpMethod;
import org.springframework.http.server.PathContainer;
import org.springframework.http.server.RequestPath;
import org.springframework.lang.Nullable;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.security.web.util.matcher.MethodPatternRequestMatcherFactory;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.util.ServletRequestPathUtils;
import org.springframework.web.util.pattern.PathPattern;
import org.springframework.web.util.pattern.PathPatternParser;

/**
 * A {@link RequestMatcher} that uses {@link PathPattern}s to match against each
 * {@link HttpServletRequest}. The provided path should be relative to the servlet (that
 * is, it should exclude any context or servlet path).
 *
 * <p>
 * To also match the servlet, please see {@link PathPatternRequestMatcher#servletPath}
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
	 * Create a {@link PathPatternRequestMatcher} whose URIs do not have a servlet path
	 * prefix
	 * <p>
	 * When there is no context path, then these URIs are effectively absolute.
	 * @return a {@link Builder} that treats URIs as relative to the context path, if any
	 */
	public static Builder path() {
		return new Builder();
	}

	/**
	 * Create a {@link PathPatternRequestMatcher} whose URIs are relative to the given
	 * {@code servletPath} prefix.
	 *
	 * <p>
	 * The {@code servletPath} must correlate to a value that would match the result of
	 * {@link HttpServletRequest#getServletPath()} and its corresponding servlet.
	 *
	 * <p>
	 * That is, if you have a servlet mapping of {@code /path/*}, then
	 * {@link HttpServletRequest#getServletPath()} would return {@code /path} and so
	 * {@code /path} is what is specified here.
	 *
	 * <p>
	 * Specify the path here without the trailing {@code /*}.
	 * @return a {@link Builder} that treats URIs as relative to the given
	 * {@code servletPath}
	 */
	public static Builder servletPath(String servletPath) {
		return new Builder().servletPath(servletPath);
	}

	/**
	 * Use this {@link PathPatternParser} to parse path patterns. Uses
	 * {@link PathPatternParser#defaultInstance} by default.
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
		PathContainer path = getRequestPath(request).pathWithinApplication();
		PathPattern.PathMatchInfo info = this.pattern.matchAndExtract(path);
		return (info != null) ? MatchResult.match(info.getUriVariables()) : MatchResult.notMatch();
	}

	void setMethod(RequestMatcher method) {
		this.method = method;
	}

	void setServletPath(RequestMatcher servletPath) {
		this.servletPath = servletPath;
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
		StringBuilder request = new StringBuilder();
		if (this.method instanceof HttpMethodRequestMatcher m) {
			request.append(m.method.name()).append(' ');
		}
		if (this.servletPath instanceof ServletPathRequestMatcher s) {
			request.append(s.path);
		}
		return "PathPattern [" + request + this.pattern + "]";
	}

	/**
	 * A builder for specifying various elements of a request for the purpose of creating
	 * a {@link PathPatternRequestMatcher}.
	 *
	 * <p>
	 * For example, if Spring MVC is deployed to `/mvc` and another servlet to `/other`,
	 * then you can use this builder to do:
	 * </p>
	 *
	 * <code>
	 *     http
	 *         .authorizeHttpRequests((authorize) -> authorize
	 *              .requestMatchers(servletPath("/mvc").matcher("/user/**")).hasAuthority("user")
	 *              .requestMatchers(servletPath("/other").matcher("/admin/**")).hasAuthority("admin")
	 *         )
	 *             ...
	 * </code>
	 */
	public static final class Builder implements MethodPatternRequestMatcherFactory {

		private final PathPatternParser parser;

		private RequestMatcher servletPath = AnyRequestMatcher.INSTANCE;

		private Builder() {
			this.parser = PathPatternParser.defaultInstance;
		}

		private Builder(PathPatternParser parser) {
			this.parser = parser;
		}

		/**
		 * Match requests starting with this {@code servletPath}.
		 * @param servletPath the servlet path prefix
		 * @see PathPatternRequestMatcher#servletPath
		 * @return the {@link Builder} for more configuration
		 */
		public Builder servletPath(String servletPath) {
			this.servletPath = new ServletPathRequestMatcher(servletPath);
			return this;
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
		 * @param pattern the path pattern to match
		 * @return the {@link Builder} for more configuration
		 */
		public PathPatternRequestMatcher matcher(@Nullable HttpMethod method, String pattern) {
			Assert.notNull(pattern, "pattern cannot be null");
			Assert.isTrue(pattern.startsWith("/"), "pattern must start with a /");
			PathPattern pathPattern = this.parser.parse(pattern);
			PathPatternRequestMatcher requestMatcher = new PathPatternRequestMatcher(pathPattern);
			if (method != null) {
				requestMatcher.setMethod(new HttpMethodRequestMatcher(method));
			}
			if (this.servletPath != AnyRequestMatcher.INSTANCE) {
				requestMatcher.setServletPath(this.servletPath);
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

	private static final class ServletPathRequestMatcher implements RequestMatcher {

		private final String path;

		private final AtomicReference<Boolean> servletExists = new AtomicReference<>();

		ServletPathRequestMatcher(String servletPath) {
			Assert.notNull(servletPath, "servletPath cannot be null");
			Assert.isTrue(servletPath.startsWith("/"), "servletPath must start with '/'");
			Assert.isTrue(!servletPath.endsWith("/"), "servletPath must not end with a slash");
			Assert.isTrue(!servletPath.contains("*"), "servletPath must not contain a star");
			this.path = servletPath;
		}

		@Override
		public boolean matches(HttpServletRequest request) {
			Assert.isTrue(servletExists(request), () -> this.path + "/* does not exist in your servlet registration "
					+ registrationMappings(request));
			return Objects.equals(this.path, ServletRequestPathUtils.getServletPathPrefix(request));
		}

		private boolean servletExists(HttpServletRequest request) {
			return this.servletExists.updateAndGet((value) -> {
				if (value != null) {
					return value;
				}
				if (request.getAttribute("org.springframework.test.web.servlet.MockMvc.MVC_RESULT_ATTRIBUTE") != null) {
					return true;
				}
				for (ServletRegistration registration : request.getServletContext()
					.getServletRegistrations()
					.values()) {
					if (registration.getMappings().contains(this.path + "/*")) {
						return true;
					}
				}
				return false;
			});
		}

		private Map<String, Collection<String>> registrationMappings(HttpServletRequest request) {
			Map<String, Collection<String>> map = new LinkedHashMap<>();
			ServletContext servletContext = request.getServletContext();
			for (ServletRegistration registration : servletContext.getServletRegistrations().values()) {
				map.put(registration.getName(), registration.getMappings());
			}
			return map;
		}

		@Override
		public String toString() {
			return "ServletPath [" + this.path + "]";
		}

	}

}
