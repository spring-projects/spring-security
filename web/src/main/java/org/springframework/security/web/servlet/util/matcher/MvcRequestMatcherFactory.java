/*
 * Copyright 2002-2024 the original author or authors.
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

import jakarta.servlet.ServletRegistration;
import jakarta.servlet.http.HttpServletMapping;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.MappingMatch;

import org.springframework.http.HttpMethod;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcherFactory;
import org.springframework.util.Assert;
import org.springframework.web.servlet.DispatcherServlet;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

/**
 * A {@link RequestMatcherFactory} that builder {@link RequestMatcher} instances that
 * first check to see if the request is a Spring MVC request. If so, it matches using
 * {@link HandlerMappingIntrospector}. If it's not an MVC request, it falls back to ant
 * path request matching.
 *
 * <p>
 * Note that this implementation is stricter than {@link MvcRequestMatcher} in that it
 * requires {@link MvcRequestMatcher#setServletPath} be configured if Spring MVC has a
 * custom servlet path.
 * </p>
 *
 * @author Josh Cummings
 * @since 6.4
 */
public final class MvcRequestMatcherFactory implements RequestMatcherFactory {

	private final HandlerMappingIntrospector introspector;

	private final RequestMatcher isMvcRequest;

	private String servletPath;

	MvcRequestMatcherFactory(HandlerMappingIntrospector introspector) {
		this(introspector, null);
	}

	MvcRequestMatcherFactory(HandlerMappingIntrospector introspector, String servletPath) {
		this.introspector = introspector;
		if (servletPath != null) {
			Assert.isTrue(servletPath.startsWith("/") && !servletPath.endsWith("/*"),
					"Please sure the each servlet path is of the format /path");
		}
		this.servletPath = servletPath;
		this.isMvcRequest = new OrRequestMatcher(new MockMvcRequestMatcher(),
				new DispatcherServletRequestMatcher(this.introspector));
	}

	/**
	 * Use the following {@link HandlerMappingIntrospector}.
	 * @param introspector
	 * @return
	 */
	public static Builder builder(HandlerMappingIntrospector introspector) {
		return new Builder(introspector);
	}

	/**
	 * @inheritDoc
	 */
	@Override
	public RequestMatcher requestMatcher(HttpMethod method, String pattern) {
		Assert.isTrue(pattern.startsWith("/"), "Please ensure that all patterns start with a /");
		AntPathRequestMatcher ant = new AntPathRequestMatcher(pattern, (method != null) ? method.name() : null);
		MvcRequestMatcher mvc = new StrictMvcRequestMatcher(this.introspector, pattern);
		mvc.setMethod(method);
		mvc.setServletPath(this.servletPath);
		mvc.setDefaultMatcher((request) -> false);
		return new MvcDelegatingRequestMatcher(ant, mvc, this.isMvcRequest);
	}

	public static final class Builder {

		private HandlerMappingIntrospector introspector;

		private String servletPath;

		private Builder(HandlerMappingIntrospector introspector) {
			this.introspector = introspector;
		}

		public Builder servletPath(String servletPath) {
			this.servletPath = servletPath;
			return this;
		}

		public MvcRequestMatcherFactory build() {
			return new MvcRequestMatcherFactory(this.introspector, this.servletPath);
		}

	}

	/**
	 * MockMvc does not populate the entire servlet registration. However, it's reasonable
	 * to assume that if a request is using MockMvc, then it is targeting MVC endpoints.
	 */
	static class MockMvcRequestMatcher implements RequestMatcher {

		@Override
		public boolean matches(HttpServletRequest request) {
			return request.getAttribute("org.springframework.test.web.servlet.MockMvc.MVC_RESULT_ATTRIBUTE") != null;
		}

	}

	static class DispatcherServletRequestMatcher implements RequestMatcher {

		private final HandlerMappingIntrospector introspector;

		DispatcherServletRequestMatcher(HandlerMappingIntrospector introspector) {
			this.introspector = introspector;
		}

		@Override
		public boolean matches(HttpServletRequest request) {
			String name = request.getHttpServletMapping().getServletName();
			ServletRegistration registration = request.getServletContext().getServletRegistration(name);
			if (registration != null) {
				return isDispatcherServlet(registration);
			}
			// in some testing scenarios, the servlet context is not configured, so fall
			// back to introspection
			return foundMapping(request);
		}

		private boolean isDispatcherServlet(ServletRegistration registration) {
			try {
				Class<?> clazz = Class.forName(registration.getClassName());
				return DispatcherServlet.class.isAssignableFrom(clazz);
			}
			catch (ClassNotFoundException ex) {
				throw new IllegalStateException(ex);
			}
		}

		private boolean foundMapping(HttpServletRequest request) {
			try {
				return this.introspector.getMatchableHandlerMapping(request) != null;
			}
			catch (Exception ex) {
				throw new IllegalStateException(ex);
			}
		}

	}

	static class MvcDelegatingRequestMatcher implements RequestMatcher {

		private final RequestMatcher ant;

		private final RequestMatcher mvc;

		private final RequestMatcher isMvcRequest;

		MvcDelegatingRequestMatcher(RequestMatcher ant, RequestMatcher mvc, RequestMatcher isMvcRequest) {
			this.ant = ant;
			this.mvc = mvc;
			this.isMvcRequest = isMvcRequest;
		}

		RequestMatcher requestMatcher(HttpServletRequest request) {
			return (this.isMvcRequest.matches(request)) ? this.mvc : this.ant;
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
			return "MvcDelegating [ant = " + this.ant + ", mvc = " + this.mvc + "]";
		}

	}

	/**
	 * A matcher implementation that errors if {@link DispatcherServlet} is mapped to a
	 * path and this matcher does not have a servlet path specified.
	 */
	static final class StrictMvcRequestMatcher extends MvcRequestMatcher {

		StrictMvcRequestMatcher(HandlerMappingIntrospector introspector, String pattern) {
			super(introspector, pattern);
		}

		private void validateConfiguration(HttpServletRequest request) {
			String requestServletPath = getRequestServletPath(request);
			String configuredServletPath = getServletPath();
			Assert.state(requestServletPath == null || configuredServletPath != null,
					String.format(
							"It appears the Spring MVC servlet path is not root. "
									+ "Please provide the servlet path %s when constructing MvcRequestMatcherFactory",
							requestServletPath));
		}

		@Override
		public boolean matches(HttpServletRequest request) {
			validateConfiguration(request);
			return super.matches(request);
		}

		@Override
		public MatchResult matcher(HttpServletRequest request) {
			validateConfiguration(request);
			return super.matcher(request);
		}

		private String getRequestServletPath(HttpServletRequest request) {
			HttpServletMapping mapping = request.getHttpServletMapping();
			if (mapping == null) {
				// some testing scenarios do not configure a servlet mapping, so we cannot
				// validate
				return null;
			}
			if (mapping.getMappingMatch() != MappingMatch.PATH) {
				return null;
			}
			String servletMapping = mapping.getPattern();
			if (servletMapping.length() <= 2) {
				// this is either an EXACT or a CONTEXT_ROOT match so we'll ignore
				return null;
			}
			if (!servletMapping.endsWith("/*")) {
				// this is an EXACT match so we'll ignore
				return null;
			}
			return servletMapping.substring(0, servletMapping.length() - 2);
		}

	}

}
