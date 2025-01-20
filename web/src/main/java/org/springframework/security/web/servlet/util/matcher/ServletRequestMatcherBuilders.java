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
import java.util.concurrent.ConcurrentHashMap;

import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletRegistration;
import jakarta.servlet.http.HttpServletRequest;

import org.springframework.http.HttpMethod;
import org.springframework.security.web.servlet.util.matcher.ServletRegistrationsSupport.RegistrationMapping;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcherBuilder;
import org.springframework.util.Assert;
import org.springframework.web.servlet.DispatcherServlet;

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
	 * Create {@link RequestMatcher}s that will only match URIs against the default
	 * servlet.
	 * @return a {@link ServletRequestMatcherBuilders} that matches URIs mapped to the
	 * default servlet
	 */
	public static RequestMatcherBuilder defaultServlet() {
		return servletPathInternal("");
	}

	/**
	 * Create {@link RequestMatcher}s that will only match URIs against the given servlet
	 * path
	 *
	 * <p>
	 * The path must be of the format {@code /path}. It should not end in `/` or `/*`, nor
	 * should it be a file extension. To specify the default servlet, use
	 * {@link #defaultServlet()}.
	 * </p>
	 * @return a {@link ServletRequestMatcherBuilders} that matches URIs mapped to the
	 * given servlet path
	 */
	public static RequestMatcherBuilder servletPath(String servletPath) {
		Assert.notNull(servletPath, "servletPath cannot be null");
		Assert.isTrue(servletPath.startsWith("/"), "servletPath must start with '/'");
		Assert.isTrue(!servletPath.endsWith("/"), "servletPath must not end with '/'");
		Assert.isTrue(!servletPath.endsWith("/*"), "servletPath must not end with '/*'");
		return servletPathInternal(servletPath);
	}

	private static RequestMatcherBuilder servletPathInternal(String servletPath) {
		return (method, pattern) -> {
			Assert.notNull(pattern, "pattern cannot be null");
			Assert.isTrue(pattern.startsWith("/"), "pattern must start with '/'");
			return PathPatternRequestMatcher.builder().servletPath(servletPath).pattern(method, pattern);
		};
	}

	/**
	 * Create {@link RequestMatcher}s that will deduce the servlet path by testing the
	 * given patterns as relative and absolute. If the target servlet is
	 * {@link DispatcherServlet}, then it tests the pattern as relative to the servlet
	 * path; otherwise, it tests the pattern as absolute
	 * @return a {@link ServletRequestMatcherBuilders} that deduces the servlet path at
	 * request time
	 */
	public static RequestMatcherBuilder servletPathDeducing() {
		return (method, pattern) -> {
			Assert.notNull(pattern, "pattern cannot be null");
			Assert.isTrue(pattern.startsWith("/"), "pattern must start with '/'");
			return new PathDeducingRequestMatcher(method, pattern);
		};
	}

	static final class PathDeducingRequestMatcher implements RequestMatcher {

		private static final RequestMatcher isMockMvc = (request) -> request
			.getAttribute("org.springframework.test.web.servlet.MockMvc.MVC_RESULT_ATTRIBUTE") != null;

		private static final RequestMatcher isDispatcherServlet = (request) -> {
			String name = request.getHttpServletMapping().getServletName();
			ServletContext servletContext = request.getServletContext();
			ServletRegistration registration = servletContext.getServletRegistration(name);
			Assert.notNull(registration, () -> computeErrorMessage(servletContext.getServletRegistrations().values()));
			String mapping = request.getHttpServletMapping().getPattern();
			return new RegistrationMapping(registration, mapping).isDispatcherServlet();
		};

		private final Map<ServletContext, RequestMatcher> delegates = new ConcurrentHashMap<>();

		private HttpMethod method;

		private String pattern;

		PathDeducingRequestMatcher(HttpMethod method, String pattern) {
			this.method = method;
			this.pattern = pattern;
		}

		RequestMatcher requestMatcher(HttpServletRequest request) {
			return this.delegates.computeIfAbsent(request.getServletContext(), (servletContext) -> {
				PathPatternRequestMatcher absolute = PathPatternRequestMatcher.builder()
					.pattern(this.method, this.pattern);
				PathPatternRequestMatcher relative = PathPatternRequestMatcher.builder()
					.pattern(this.method, this.pattern);
				ServletRegistrationsSupport registrations = new ServletRegistrationsSupport(servletContext);
				Collection<RegistrationMapping> mappings = registrations.mappings();
				if (mappings.isEmpty()) {
					relative.setServletPath(PathPatternRequestMatcher.ANY_SERVLET);
					return new EitherRequestMatcher(relative, absolute, isMockMvc);
				}
				Collection<RegistrationMapping> dispatcherServletMappings = registrations.dispatcherServletMappings();
				if (dispatcherServletMappings.isEmpty()) {
					relative.setServletPath(PathPatternRequestMatcher.ANY_SERVLET);
					return new EitherRequestMatcher(relative, absolute, isMockMvc);
				}
				if (dispatcherServletMappings.size() > 1) {
					String errorMessage = computeErrorMessage(servletContext.getServletRegistrations().values());
					throw new IllegalArgumentException(errorMessage);
				}
				RegistrationMapping dispatcherServlet = dispatcherServletMappings.iterator().next();
				if (mappings.size() > 1 && !dispatcherServlet.isDefault()) {
					String errorMessage = computeErrorMessage(servletContext.getServletRegistrations().values());
					throw new IllegalArgumentException(errorMessage);
				}
				if (dispatcherServlet.isDefault()) {
					relative.setServletPath("");
					if (mappings.size() == 1) {
						return relative;
					}
					return new EitherRequestMatcher(relative, absolute,
							new OrRequestMatcher(isMockMvc, isDispatcherServlet));
				}
				String mapping = dispatcherServlet.mapping();
				relative.setServletPath(mapping.substring(0, mapping.length() - 2));
				return relative;
			});
		}

		@Override
		public boolean matches(HttpServletRequest request) {
			return matcher(request).isMatch();
		}

		@Override
		public MatchResult matcher(HttpServletRequest request) {
			return requestMatcher(request).matcher(request);
		}

		private static String computeErrorMessage(Collection<? extends ServletRegistration> registrations) {
			String template = """
					This method cannot decide whether these patterns are Spring MVC patterns or not. \
					This is because there is more than one mappable servlet in your servlet context: %s.

					To address this, please create one ServletRequestMatcherBuilder#servletPath for each servlet that has \
					authorized endpoints and use them to construct request matchers manually. \
					If all your URIs are unambiguous, then you can simply publish one ServletRequestMatcherBuilders#servletPath as \
					a @Bean and Spring Security will use it for all URIs""";
			Map<String, Collection<String>> mappings = new LinkedHashMap<>();
			for (ServletRegistration registration : registrations) {
				mappings.put(registration.getClassName(), registration.getMappings());
			}
			return String.format(template, mappings);
		}

		@Override
		public String toString() {
			return "PathDeducingRequestMatcher [delegates = " + this.delegates + "]";
		}

	}

	static class EitherRequestMatcher implements RequestMatcher {

		final RequestMatcher right;

		final RequestMatcher left;

		final RequestMatcher test;

		EitherRequestMatcher(RequestMatcher right, RequestMatcher left, RequestMatcher test) {
			this.left = left;
			this.right = right;
			this.test = test;
		}

		RequestMatcher requestMatcher(HttpServletRequest request) {
			return this.test.matches(request) ? this.right : this.left;
		}

		@Override
		public boolean matches(HttpServletRequest request) {
			return requestMatcher(request).matches(request);
		}

		@Override
		public MatchResult matcher(HttpServletRequest request) {
			return requestMatcher(request).matcher(request);
		}

		@Override
		public String toString() {
			return "Either [" + "left = " + this.left + ", right = " + this.right + "]";
		}

	}

}
