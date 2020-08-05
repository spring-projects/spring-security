/*
 * Copyright 2002-2016 the original author or authors.
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
package org.springframework.security.web.savedrequest;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.util.Assert;
import org.springframework.web.filter.GenericFilterBean;

/**
 * Responsible for reconstituting the saved request if one is cached and it matches the
 * current request.
 * <p>
 * It will call
 * {@link RequestCache#getMatchingRequest(HttpServletRequest, HttpServletResponse)
 * getMatchingRequest} on the configured <tt>RequestCache</tt>. If the method returns a
 * value (a wrapper of the saved request), it will pass this to the filter chain's
 * <tt>doFilter</tt> method. If null is returned by the cache, the original request is
 * used and the filter has no effect.
 *
 * @author Luke Taylor
 * @since 3.0
 */
public class RequestCacheAwareFilter extends GenericFilterBean {

	private RequestCache requestCache;

	public RequestCacheAwareFilter() {
		this(new HttpSessionRequestCache());
	}

	public RequestCacheAwareFilter(RequestCache requestCache) {
		Assert.notNull(requestCache, "requestCache cannot be null");
		this.requestCache = requestCache;
	}

	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {

		HttpServletRequest wrappedSavedRequest = requestCache.getMatchingRequest((HttpServletRequest) request,
				(HttpServletResponse) response);

		chain.doFilter(wrappedSavedRequest == null ? request : wrappedSavedRequest, response);
	}

}
