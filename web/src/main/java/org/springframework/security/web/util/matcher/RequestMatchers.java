/*
 * Copyright 2002-2023 the original author or authors.
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

import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import jakarta.servlet.DispatcherType;
import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletRegistration;
import jakarta.servlet.http.HttpServletMapping;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.MappingMatch;

import org.springframework.http.HttpMethod;
import org.springframework.lang.Nullable;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.ObjectUtils;
import org.springframework.web.util.UriUtils;
import org.springframework.web.util.WebUtils;
import org.springframework.web.util.pattern.PathPattern;
import org.springframework.web.util.pattern.PathPatternParser;

/**
 * A factory class to create {@link RequestMatcher} instances.
 *
 * @author Christian Schuster
 * @since 6.1
 */
public final class RequestMatchers {

	/**
	 * Creates a {@link RequestMatcher} that matches if at least one of the given
	 * {@link RequestMatcher}s matches, if <code>matchers</code> are empty then the
	 * returned matcher never matches.
	 * @param matchers the {@link RequestMatcher}s to use
	 * @return the any-of composed {@link RequestMatcher}
	 * @see OrRequestMatcher
	 */
	public static RequestMatcher anyOf(RequestMatcher... matchers) {
		return (matchers.length > 0) ? new OrRequestMatcher(List.of(matchers)) : (request) -> false;
	}

	/**
	 * Creates a {@link RequestMatcher} that matches if all the given
	 * {@link RequestMatcher}s match, if <code>matchers</code> are empty then the returned
	 * matcher always matches.
	 * @param matchers the {@link RequestMatcher}s to use
	 * @return the all-of composed {@link RequestMatcher}
	 * @see AndRequestMatcher
	 */
	public static RequestMatcher allOf(RequestMatcher... matchers) {
		return (matchers.length > 0) ? new AndRequestMatcher(List.of(matchers)) : (request) -> true;
	}

	/**
	 * Creates a {@link RequestMatcher} that matches if the given {@link RequestMatcher}
	 * does not match.
	 * @param matcher the {@link RequestMatcher} to use
	 * @return the inverted {@link RequestMatcher}
	 */
	public static RequestMatcher not(RequestMatcher matcher) {
		return (request) -> !matcher.matches(request);
	}

	/**
	 * Create {@link RequestMatcher}s whose URIs do not have a servlet path prefix
	 * <p>
	 * When there is no context path, then these URIs are effectively absolute.
	 * @return a {@link Builder} that treats URIs as relative to the context path, if any
	 * @since 6.5
	 */
	public static Builder request() {
		return new Builder();
	}

	/**
	 * Create {@link RequestMatcher}s whose URIs are relative to the given
	 * {@code servletPath}.
	 *
	 * <p>
	 * The {@code servletPath} must correlate to a configured servlet in your application.
	 * The path must be of the format {@code /path}.
	 * @return a {@link Builder} that treats URIs as relative to the given
	 * {@code servletPath}
	 * @since 6.5
	 */
	public static Builder servlet(String servletPath) {
		Assert.notNull(servletPath, "servletPath cannot be null");
		Assert.isTrue(servletPath.startsWith("/"), "servletPath must start with '/'");
		Assert.isTrue(!servletPath.endsWith("/"), "servletPath must not end with a slash");
		Assert.isTrue(!servletPath.contains("*"), "servletPath must not contain a star");
		return new Builder(servletPath);
	}

	private RequestMatchers() {
	}

	/**
	 * A builder for specifying various elements of a request for the purpose of creating
	 * a {@link RequestMatcher}.
	 *
	 * <p>
	 * For example, if Spring MVC is deployed to `/mvc` and another servlet to `/other`,
	 * then you can do:
	 * </p>
	 *
	 * <code>
	 *     http
	 *         .authorizeHttpRequests((authorize) -> authorize
	 *              .requestMatchers(servlet("/mvc").uris("/user/**")).hasAuthority("user")
	 *              .requestMatchers(servlet("/other").uris("/admin/**")).hasAuthority("admin")
	 *         )
	 *             ...
	 * </code>
	 *
	 * @author Josh Cummings
	 * @since 6.5
	 */
	public static final class Builder {

		private final RequestMatcher servletPath;

		private final RequestMatcher methods;

		private final RequestMatcher uris;

		private final RequestMatcher dispatcherTypes;

		private final RequestMatcher matchers;

		private Builder() {
			this(AnyRequestMatcher.INSTANCE, AnyRequestMatcher.INSTANCE, AnyRequestMatcher.INSTANCE,
					AnyRequestMatcher.INSTANCE, AnyRequestMatcher.INSTANCE);
		}

		private Builder(String servletPath) {
			this(new ServletPathRequestMatcher(servletPath), AnyRequestMatcher.INSTANCE, AnyRequestMatcher.INSTANCE,
					AnyRequestMatcher.INSTANCE, AnyRequestMatcher.INSTANCE);
		}

		private Builder(RequestMatcher servletPath, RequestMatcher methods, RequestMatcher uris,
				RequestMatcher dispatcherTypes, RequestMatcher matchers) {
			this.servletPath = servletPath;
			this.methods = methods;
			this.uris = uris;
			this.dispatcherTypes = dispatcherTypes;
			this.matchers = matchers;
		}

		/**
		 * Match requests with any of these methods
		 * @param methods the {@link HttpMethod} to match
		 * @return the {@link Builder} for more configuration
		 */
		public Builder methods(HttpMethod... methods) {
			RequestMatcher[] matchers = new RequestMatcher[methods.length];
			for (int i = 0; i < methods.length; i++) {
				matchers[i] = new HttpMethodRequestMatcher(methods[i]);
			}
			return new Builder(this.servletPath, anyOf(matchers), this.uris, this.dispatcherTypes, this.matchers);
		}

		/**
		 * Match requests with any of these URIs
		 *
		 * <p>
		 * URIs can be Ant patterns like {@code /path/**}.
		 * @param uris the URIs to match
		 * @return the {@link Builder} for more configuration
		 */
		public Builder uris(String... uris) {
			RequestMatcher[] matchers = new RequestMatcher[uris.length];
			for (int i = 0; i < uris.length; i++) {
				Assert.isTrue(uris[i].startsWith("/"), "pattern must start with '/'");
				PathPatternParser parser = PathPatternParser.defaultInstance;
				matchers[i] = new PathPatternRequestMatcher(parser.parse(uris[i]));
			}
			return new Builder(this.servletPath, this.methods, anyOf(matchers), this.dispatcherTypes, this.matchers);
		}

		/**
		 * Match requests with any of these {@link PathPattern}s
		 *
		 * <p>
		 * Use this when you have a non-default {@link PathPatternParser}
		 * @param uris the URIs to match
		 * @return the {@link Builder} for more configuration
		 */
		public Builder uris(PathPattern... uris) {
			RequestMatcher[] matchers = new RequestMatcher[uris.length];
			for (int i = 0; i < uris.length; i++) {
				matchers[i] = new PathPatternRequestMatcher(uris[i]);
			}
			return new Builder(this.servletPath, this.methods, anyOf(matchers), this.dispatcherTypes, this.matchers);
		}

		/**
		 * Match requests with any of these dispatcherTypes
		 *
		 * <p>
		 * URIs can be Ant patterns like {@code /path/**}.
		 * @param dispatcherTypes the {@link DispatcherType}s to match
		 * @return the {@link Builder} for more configuration
		 */
		public Builder dispatcherTypes(DispatcherType... dispatcherTypes) {
			RequestMatcher[] matchers = new RequestMatcher[dispatcherTypes.length];
			for (int i = 0; i < dispatcherTypes.length; i++) {
				matchers[i] = new DispatcherTypeRequestMatcher(dispatcherTypes[i]);
			}
			return new Builder(this.servletPath, this.methods, this.uris, anyOf(matchers), this.matchers);
		}

		/**
		 * Match requests with any of these {@link RequestMatcher}s
		 * @param requestMatchers the {@link RequestMatchers}s to match
		 * @return the {@link Builder} for more configuration
		 */
		public Builder matching(RequestMatcher... requestMatchers) {
			return new Builder(this.servletPath, this.methods, this.uris, this.dispatcherTypes, anyOf(requestMatchers));
		}

		/**
		 * Create the {@link RequestMatcher}
		 * @return the composite {@link RequestMatcher}
		 */
		public RequestMatcher matcher() {
			return allOf(this.servletPath, this.methods, this.uris, this.dispatcherTypes, this.matchers);
		}

	}

	private record HttpMethodRequestMatcher(HttpMethod method) implements RequestMatcher {

		@Override
		public boolean matches(HttpServletRequest request) {
			return this.method.name().equals(request.getMethod());
		}

		@Override
		public String toString() {
			return "HttpMethod [" + this.method + "]";
		}

	}

	private record ServletPathRequestMatcher(String path) implements RequestMatcher {

		@Override
		public boolean matches(HttpServletRequest request) {
			Assert.isTrue(servletExists(request), () -> this.path + "/* does not exist in your servlet registration "
					+ registrationMappings(request));
			return Objects.equals(this.path, getServletPathPrefix(request));
		}

		private boolean servletExists(HttpServletRequest request) {
			if (request.getAttribute("org.springframework.test.web.servlet.MockMvc.MVC_RESULT_ATTRIBUTE") != null) {
				return true;
			}
			ServletContext servletContext = request.getServletContext();
			for (ServletRegistration registration : servletContext.getServletRegistrations().values()) {
				if (registration.getMappings().contains(this.path + "/*")) {
					return true;
				}
			}
			return false;
		}

		private Map<String, Collection<String>> registrationMappings(HttpServletRequest request) {
			Map<String, Collection<String>> map = new LinkedHashMap<>();
			ServletContext servletContext = request.getServletContext();
			for (ServletRegistration registration : servletContext.getServletRegistrations().values()) {
				map.put(registration.getName(), registration.getMappings());
			}
			return map;
		}

		@Nullable
		private static String getServletPathPrefix(HttpServletRequest request) {
			HttpServletMapping mapping = (HttpServletMapping) request.getAttribute(RequestDispatcher.INCLUDE_MAPPING);
			mapping = (mapping != null) ? mapping : request.getHttpServletMapping();
			if (ObjectUtils.nullSafeEquals(mapping.getMappingMatch(), MappingMatch.PATH)) {
				String servletPath = (String) request.getAttribute(WebUtils.INCLUDE_SERVLET_PATH_ATTRIBUTE);
				servletPath = (servletPath != null) ? servletPath : request.getServletPath();
				servletPath = servletPath.endsWith("/") ? servletPath.substring(0, servletPath.length() - 1)
						: servletPath;
				return UriUtils.encodePath(servletPath, StandardCharsets.UTF_8);
			}
			return null;
		}

		@Override
		public String toString() {
			return "ServletPath [" + this.path + "]";
		}
	}

}
