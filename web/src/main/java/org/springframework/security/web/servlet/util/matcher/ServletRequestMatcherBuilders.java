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

import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletRegistration;
import jakarta.servlet.http.HttpServletMapping;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.MappingMatch;

import org.springframework.http.HttpMethod;
import org.springframework.lang.Nullable;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcherBuilder;
import org.springframework.util.Assert;
import org.springframework.util.ObjectUtils;
import org.springframework.web.util.UriUtils;
import org.springframework.web.util.WebUtils;

/**
 * A {@link RequestMatcherBuilder} for specifying the servlet path separately from the
 * rest of the URI. This is helpful when you have more than one servlet.
 *
 * <p>
 * For example, if Spring MVC is deployed to `/mvc` and another servlet to `/other`, then
 * you can do
 * </p>
 *
 * <code>
 *     http
 *         .authorizeHttpRequests((authorize) -> authorize
 *         		.requestMatchers(servletPath("/mvc").pattern("/my/**", "/controller/**", "/endpoints/**")).hasAuthority(...
 *         		.requestMatchers(servletPath("/other").pattern("/my/**", "/non-mvc/**", "/endpoints/**")).hasAuthority(...
 *         	}
 *         	...
 * </code>
 *
 * @author Josh Cummings
 * @since 6.5
 */
public final class ServletRequestMatcherBuilders {

	private ServletRequestMatcherBuilders() {
	}

	/**
	 * Create {@link RequestMatcher}s whose URIs are relative to the context path, if any.
	 * <p>
	 * When there is no context path, then these URIs are effectively absolute.
	 * @return a {@link RequestMatcherBuilder} that treats URIs as relative to the context
	 * path, if any
	 */
	public static RequestMatcherBuilder requestPath() {
		return PathPatternRequestMatcher::pathPattern;
	}

	/**
	 * Create {@link RequestMatcher}s whose URIs are relative to the given
	 * {@code servletPath}.
	 *
	 * <p>
	 * The {@code servletPath} must correlate to a configured servlet in your application.
	 * The path must be of the format {@code /path}.
	 * @return a {@link RequestMatcherBuilder} that treats URIs as relative to the given
	 * {@code servletPath}
	 */
	public static RequestMatcherBuilder servletPath(String servletPath) {
		Assert.notNull(servletPath, "servletPath cannot be null");
		Assert.isTrue(servletPath.startsWith("/"), "servletPath must start with '/'");
		Assert.isTrue(!servletPath.endsWith("/"), "servletPath must not end with a slash");
		Assert.isTrue(!servletPath.contains("*"), "servletPath must not contain a star");
		return new ServletRequestMatcherBuilder(servletPath);
	}

	private record ServletRequestMatcherBuilder(String servletPath) implements RequestMatcherBuilder {
		@Override
		public RequestMatcher anyRequest() {
			return new ServletPathRequestMatcher(this.servletPath);
		}

		@Override
		public RequestMatcher matcher(HttpMethod method, String pattern) {
			Assert.notNull(pattern, "pattern cannot be null");
			Assert.isTrue(pattern.startsWith("/"), "pattern must start with '/'");
			PathPatternRequestMatcher pathPattern = PathPatternRequestMatcher.pathPattern(method,
					this.servletPath + pattern);
			return new AndRequestMatcher(new ServletPathRequestMatcher(this.servletPath), pathPattern);
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
	}

}
