/*
 * Copyright 2012-2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.web.servlet.util.matcher;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.http.HttpMethod;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.util.matcher.RequestVariablesExtractor;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.ClassUtils;
import org.springframework.util.PathMatcher;
import org.springframework.web.context.ServletContextAware;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;
import org.springframework.web.servlet.handler.MatchableHandlerMapping;
import org.springframework.web.servlet.handler.RequestMatchResult;
import org.springframework.web.util.UrlPathHelper;

import javax.servlet.ServletContext;
import javax.servlet.ServletRegistration;
import javax.servlet.http.HttpServletRequest;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;

/**
 * A {@link RequestMatcher} that uses Spring MVC's {@link HandlerMappingIntrospector} to
 * match the path and extract variables.
 *
 * <p>
 * It is important to understand that Spring MVC's matching is relative to the servlet
 * path. This means if you have mapped any servlet to a path that starts with "/" and is
 * greater than one, you should also specify the {@link #setServletPath(String)}
 * attribute to differentiate mappings.
 * </p>
 *
 * @author Rob Winch
 * @since 4.1.1
 */
public class MvcRequestMatcher
		implements RequestMatcher, RequestVariablesExtractor, InitializingBean, ServletContextAware {

	private static final boolean isServlet30 = ClassUtils.isPresent(
		"javax.servlet.ServletRegistration", MvcRequestMatcher.class.getClassLoader());

	private final DefaultMatcher defaultMatcher = new DefaultMatcher();

	private final HandlerMappingIntrospector introspector;
	private final String pattern;
	private HttpMethod method;
	private String servletPath;
	private ServletContext servletContext;

	public MvcRequestMatcher(HandlerMappingIntrospector introspector, String pattern) {
		this.introspector = introspector;
		this.pattern = pattern;
	}

	@Override
	public boolean matches(HttpServletRequest request) {
		if (this.method != null && !this.method.name().equals(request.getMethod())) {
			return false;
		}
		if (this.servletPath != null && !this.servletPath.equals(request.getServletPath())) {
			return false;
		}
		MatchableHandlerMapping mapping = getMapping(request);
		if (mapping == null) {
			return this.defaultMatcher.matches(request);
		}
		RequestMatchResult matchResult = mapping.match(request, this.pattern);
		return matchResult != null;
	}

	private MatchableHandlerMapping getMapping(HttpServletRequest request) {
		try {
			return this.introspector.getMatchableHandlerMapping(request);
		}
		catch (Throwable t) {
			return null;
		}
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see org.springframework.security.web.util.matcher.RequestVariablesExtractor#
	 * extractUriTemplateVariables(javax.servlet.http.HttpServletRequest)
	 */
	@Override
	public Map<String, String> extractUriTemplateVariables(HttpServletRequest request) {
		MatchableHandlerMapping mapping = getMapping(request);
		if (mapping == null) {
			return this.defaultMatcher.extractUriTemplateVariables(request);
		}
		RequestMatchResult result = mapping.match(request, this.pattern);
		return result == null ? Collections.<String, String>emptyMap()
				: result.extractUriTemplateVariables();
	}

	/* (non-Javadoc)
	 * @see org.springframework.beans.factory.InitializingBean#afterPropertiesSet()
	 */
	@Override
	public void afterPropertiesSet() throws Exception {
		// servletPath is required when at least one registered Servlet
		// is mapped to a path other than the default (root) path '/'
		if (this.servletContext == null || !isServlet30) {
			return;
		}
		if (this.getServletPath() != null) {
			return;
		}
		for (ServletRegistration registration : this.servletContext.getServletRegistrations().values()) {
			for (String mapping : registration.getMappings()) {
				if (mapping.startsWith("/") && mapping.length() > 1) {
					throw new IllegalStateException(
						"servletPath must not be null for mvcPattern \"" + this.getMvcPattern()
							+ "\" when providing a servlet mapping of "
							+ mapping + " for servlet "
							+ registration.getClassName());
				}
			}
		}
	}

	/* (non-Javadoc)
	 * @see org.springframework.web.context.ServletContextAware#setServletContext(javax.servlet.ServletContext)
	 */
	@Override
	public void setServletContext(ServletContext servletContext) {
		this.servletContext = servletContext;
	}

	/**
	 * @param method the method to set
	 */
	public void setMethod(HttpMethod method) {
		this.method = method;
	}

	/**
	 * The servlet path to match on. The default is undefined which means any servlet
	 * path.
	 *
	 * @param servletPath the servletPath to set
	 */
	public void setServletPath(String servletPath) {
		this.servletPath = servletPath;
	}

	protected final String getServletPath() {
		return this.servletPath;
	}

	protected final String getMvcPattern() {
		return this.pattern;
	}

	private class DefaultMatcher implements RequestMatcher, RequestVariablesExtractor {

		private final UrlPathHelper pathHelper = new UrlPathHelper();

		private final PathMatcher pathMatcher = new AntPathMatcher();

		@Override
		public boolean matches(HttpServletRequest request) {
			String lookupPath = this.pathHelper.getLookupPathForRequest(request);
			return matches(lookupPath);
		}

		private boolean matches(String lookupPath) {
			return this.pathMatcher.match(MvcRequestMatcher.this.pattern, lookupPath);
		}

		@Override
		public Map<String, String> extractUriTemplateVariables(
				HttpServletRequest request) {
			String lookupPath = this.pathHelper.getLookupPathForRequest(request);
			if (matches(lookupPath)) {
				return this.pathMatcher.extractUriTemplateVariables(
						MvcRequestMatcher.this.pattern, lookupPath);
			}
			return Collections.emptyMap();
		}
	}
}
