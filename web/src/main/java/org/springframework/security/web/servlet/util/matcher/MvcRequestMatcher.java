/*
 * Copyright 2002-2022 the original author or authors.
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

import java.util.Map;
import java.util.Objects;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.http.HttpMethod;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.util.matcher.RequestVariablesExtractor;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.PathMatcher;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;
import org.springframework.web.servlet.handler.MatchableHandlerMapping;
import org.springframework.web.servlet.handler.RequestMatchResult;
import org.springframework.web.util.UrlPathHelper;

/**
 * A {@link RequestMatcher} that uses Spring MVC's {@link HandlerMappingIntrospector} to
 * match the path and extract variables.
 *
 * <p>
 * It is important to understand that Spring MVC's matching is relative to the servlet
 * path. This means if you have mapped any servlet to a path that starts with "/" and is
 * greater than one, you should also specify the {@link #setServletPath(String)} attribute
 * to differentiate mappings.
 * </p>
 *
 * @author Rob Winch
 * @author Eddú Meléndez
 * @author Evgeniy Cheban
 * @since 4.1.1
 */
public class MvcRequestMatcher implements RequestMatcher, RequestVariablesExtractor {

	private final DefaultMatcher defaultMatcher = new DefaultMatcher();

	private final HandlerMappingIntrospector introspector;

	private final String pattern;

	private HttpMethod method;

	private String servletPath;

	public MvcRequestMatcher(HandlerMappingIntrospector introspector, String pattern) {
		this.introspector = introspector;
		this.pattern = pattern;
	}

	@Override
	public boolean matches(HttpServletRequest request) {
		if (notMatchMethodOrServletPath(request)) {
			return false;
		}
		MatchableHandlerMapping mapping = getMapping(request);
		if (mapping == null) {
			return this.defaultMatcher.matches(request);
		}
		RequestMatchResult matchResult = mapping.match(request, this.pattern);
		return matchResult != null;
	}

	@Override
	@Deprecated
	public Map<String, String> extractUriTemplateVariables(HttpServletRequest request) {
		return matcher(request).getVariables();
	}

	@Override
	public MatchResult matcher(HttpServletRequest request) {
		if (notMatchMethodOrServletPath(request)) {
			return MatchResult.notMatch();
		}
		MatchableHandlerMapping mapping = getMapping(request);
		if (mapping == null) {
			return this.defaultMatcher.matcher(request);
		}
		RequestMatchResult result = mapping.match(request, this.pattern);
		return (result != null) ? MatchResult.match(result.extractUriTemplateVariables()) : MatchResult.notMatch();
	}

	private boolean notMatchMethodOrServletPath(HttpServletRequest request) {
		return this.method != null && !this.method.name().equals(request.getMethod())
				|| this.servletPath != null && !this.servletPath.equals(request.getServletPath());
	}

	private MatchableHandlerMapping getMapping(HttpServletRequest request) {
		try {
			return this.introspector.getMatchableHandlerMapping(request);
		}
		catch (Throwable ex) {
			return null;
		}
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
	 * @param servletPath the servletPath to set
	 */
	public void setServletPath(String servletPath) {
		this.servletPath = servletPath;
	}

	protected final String getServletPath() {
		return this.servletPath;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		MvcRequestMatcher that = (MvcRequestMatcher) o;
		return Objects.equals(this.pattern, that.pattern) && Objects.equals(this.method, that.method)
				&& Objects.equals(this.servletPath, that.servletPath);
	}

	@Override
	public int hashCode() {
		return Objects.hash(this.pattern, this.method, this.servletPath);
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("Mvc [pattern='").append(this.pattern).append("'");
		if (this.servletPath != null) {
			sb.append(", servletPath='").append(this.servletPath).append("'");
		}
		if (this.method != null) {
			sb.append(", ").append(this.method);
		}
		sb.append("]");
		return sb.toString();
	}

	private class DefaultMatcher implements RequestMatcher {

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
		public MatchResult matcher(HttpServletRequest request) {
			String lookupPath = this.pathHelper.getLookupPathForRequest(request);
			if (matches(lookupPath)) {
				Map<String, String> variables = this.pathMatcher
						.extractUriTemplateVariables(MvcRequestMatcher.this.pattern, lookupPath);
				return MatchResult.match(variables);
			}
			return MatchResult.notMatch();
		}

	}

	/**
	 * A builder for {@link MvcRequestMatcher}
	 *
	 * @author Marcus Da Coregio
	 * @since 5.8
	 */
	public static final class Builder {

		private final HandlerMappingIntrospector introspector;

		private String servletPath;

		/**
		 * Construct a new instance of this builder
		 */
		public Builder(HandlerMappingIntrospector introspector) {
			this.introspector = introspector;
		}

		/**
		 * Sets the servlet path to be used by the {@link MvcRequestMatcher} generated by
		 * this builder
		 * @param servletPath the servlet path to use
		 * @return the {@link Builder} for further configuration
		 */
		public Builder servletPath(String servletPath) {
			this.servletPath = servletPath;
			return this;
		}

		/**
		 * Creates an {@link MvcRequestMatcher} that uses the provided pattern to match
		 * @param pattern the pattern used to match
		 * @return the generated {@link MvcRequestMatcher}
		 */
		public MvcRequestMatcher pattern(String pattern) {
			return pattern(null, pattern);
		}

		/**
		 * Creates an {@link MvcRequestMatcher} that uses the provided pattern and HTTP
		 * method to match
		 * @param method the {@link HttpMethod}, can be null
		 * @param pattern the patterns used to match
		 * @return the generated {@link MvcRequestMatcher}
		 */
		public MvcRequestMatcher pattern(HttpMethod method, String pattern) {
			MvcRequestMatcher mvcRequestMatcher = new MvcRequestMatcher(this.introspector, pattern);
			mvcRequestMatcher.setServletPath(this.servletPath);
			mvcRequestMatcher.setMethod(method);
			return mvcRequestMatcher;
		}

	}

}
