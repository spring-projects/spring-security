/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.web.debug;

import java.io.IOException;
import java.util.Enumeration;
import java.util.List;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.jspecify.annotations.Nullable;

import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.UrlUtils;

/**
 * Spring Security debugging filter.
 * <p>
 * Logs information (such as session creation) to help the user understand how requests
 * are being handled by Spring Security and provide them with other relevant information
 * (such as when sessions are being created).
 *
 * @author Luke Taylor
 * @author Rob Winch
 * @since 3.1
 */
public final class DebugFilter implements Filter {

	static final String ALREADY_FILTERED_ATTR_NAME = DebugFilter.class.getName().concat(".FILTERED");

	private final FilterChainProxy filterChainProxy;

	private final Logger logger = new Logger();

	public DebugFilter(FilterChainProxy filterChainProxy) {
		this.filterChainProxy = filterChainProxy;
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		if (!(request instanceof HttpServletRequest) || !(response instanceof HttpServletResponse)) {
			throw new ServletException("DebugFilter just supports HTTP requests");
		}
		doFilter((HttpServletRequest) request, (HttpServletResponse) response, filterChain);
	}

	private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws IOException, ServletException {
		List<Filter> filters = getFilters(request);
		this.logger.info("Request received for " + request.getMethod() + " '" + UrlUtils.buildRequestUrl(request)
				+ "':\n\n" + request + "\n\n" + "servletPath:" + request.getServletPath() + "\n" + "pathInfo:"
				+ request.getPathInfo() + "\n" + "headers: \n" + formatHeaders(request) + "\n\n"
				+ formatFilters(filters));
		if (request.getAttribute(ALREADY_FILTERED_ATTR_NAME) == null) {
			invokeWithWrappedRequest(request, response, filterChain);
		}
		else {
			this.filterChainProxy.doFilter(request, response, filterChain);
		}
	}

	private void invokeWithWrappedRequest(HttpServletRequest request, HttpServletResponse response,
			FilterChain filterChain) throws IOException, ServletException {
		request.setAttribute(ALREADY_FILTERED_ATTR_NAME, Boolean.TRUE);
		request = new DebugRequestWrapper(request);
		try {
			this.filterChainProxy.doFilter(request, response, filterChain);
		}
		finally {
			request.removeAttribute(ALREADY_FILTERED_ATTR_NAME);
		}
	}

	String formatHeaders(HttpServletRequest request) {
		StringBuilder sb = new StringBuilder();
		Enumeration<String> eHeaderNames = request.getHeaderNames();
		while (eHeaderNames.hasMoreElements()) {
			String headerName = eHeaderNames.nextElement();
			sb.append(headerName);
			sb.append(": ");
			Enumeration<String> eHeaderValues = request.getHeaders(headerName);
			while (eHeaderValues.hasMoreElements()) {
				sb.append(eHeaderValues.nextElement());
				if (eHeaderValues.hasMoreElements()) {
					sb.append(", ");
				}
			}
			sb.append("\n");
		}
		return sb.toString();
	}

	String formatFilters(@Nullable List<Filter> filters) {
		StringBuilder sb = new StringBuilder();
		sb.append("Security filter chain: ");
		if (filters == null) {
			sb.append("no match");
		}
		else if (filters.isEmpty()) {
			sb.append("[] empty (bypassed by security='none') ");
		}
		else {
			sb.append("[\n");
			for (Filter f : filters) {
				sb.append("  ").append(f.getClass().getSimpleName()).append("\n");
			}
			sb.append("]");
		}

		return sb.toString();
	}

	private @Nullable List<Filter> getFilters(HttpServletRequest request) {
		for (SecurityFilterChain chain : this.filterChainProxy.getFilterChains()) {
			if (chain.matches(request)) {
				return chain.getFilters();
			}
		}

		return null;
	}

	@Override
	public void init(FilterConfig filterConfig) {
	}

	@Override
	public void destroy() {
	}

	public FilterChainProxy getFilterChainProxy() {
		return this.filterChainProxy;
	}

	static class DebugRequestWrapper extends HttpServletRequestWrapper {

		private static final Logger logger = new Logger();

		DebugRequestWrapper(HttpServletRequest request) {
			super(request);
		}

		@Override
		public HttpSession getSession() {
			boolean sessionExists = super.getSession(false) != null;
			HttpSession session = super.getSession();
			if (!sessionExists) {
				DebugRequestWrapper.logger.info("New HTTP session created: " + session.getId(), true);
			}
			return session;
		}

		@Override
		public HttpSession getSession(boolean create) {
			if (!create) {
				return super.getSession(create);
			}
			return getSession();
		}

	}

}
