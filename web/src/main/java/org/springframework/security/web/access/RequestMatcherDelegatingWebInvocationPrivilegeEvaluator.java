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

package org.springframework.security.web.access;

import java.util.Collections;
import java.util.List;

import jakarta.servlet.ServletContext;
import jakarta.servlet.http.HttpServletRequest;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.util.matcher.RequestMatcherEntry;
import org.springframework.util.Assert;
import org.springframework.web.context.ServletContextAware;

/**
 * A {@link WebInvocationPrivilegeEvaluator} which delegates to a list of
 * {@link WebInvocationPrivilegeEvaluator} based on a
 * {@link org.springframework.security.web.util.matcher.RequestMatcher} evaluation
 *
 * @author Marcus Da Coregio
 * @since 5.5.5
 */
public final class RequestMatcherDelegatingWebInvocationPrivilegeEvaluator
		implements WebInvocationPrivilegeEvaluator, ServletContextAware {

	private final List<RequestMatcherEntry<List<WebInvocationPrivilegeEvaluator>>> delegates;

	private ServletContext servletContext;

	public RequestMatcherDelegatingWebInvocationPrivilegeEvaluator(
			List<RequestMatcherEntry<List<WebInvocationPrivilegeEvaluator>>> requestMatcherPrivilegeEvaluatorsEntries) {
		Assert.notNull(requestMatcherPrivilegeEvaluatorsEntries, "requestMatcherPrivilegeEvaluators cannot be null");
		for (RequestMatcherEntry<List<WebInvocationPrivilegeEvaluator>> entry : requestMatcherPrivilegeEvaluatorsEntries) {
			Assert.notNull(entry.getRequestMatcher(), "requestMatcher cannot be null");
			Assert.notNull(entry.getEntry(), "webInvocationPrivilegeEvaluators cannot be null");
		}
		this.delegates = requestMatcherPrivilegeEvaluatorsEntries;
	}

	/**
	 * Determines whether the user represented by the supplied <tt>Authentication</tt>
	 * object is allowed to invoke the supplied URI.
	 * <p>
	 * Uses the provided URI in the
	 * {@link org.springframework.security.web.util.matcher.RequestMatcher#matches(HttpServletRequest)}
	 * for every {@code RequestMatcher} configured. If no {@code RequestMatcher} is
	 * matched, or if there is not an available {@code WebInvocationPrivilegeEvaluator},
	 * returns {@code true}.
	 * @param uri the URI excluding the context path (a default context path setting will
	 * be used)
	 * @return true if access is allowed, false if denied
	 */
	@Override
	public boolean isAllowed(String uri, Authentication authentication) {
		List<WebInvocationPrivilegeEvaluator> privilegeEvaluators = getDelegate(null, uri, null);
		if (privilegeEvaluators.isEmpty()) {
			return true;
		}
		for (WebInvocationPrivilegeEvaluator evaluator : privilegeEvaluators) {
			boolean isAllowed = evaluator.isAllowed(uri, authentication);
			if (!isAllowed) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Determines whether the user represented by the supplied <tt>Authentication</tt>
	 * object is allowed to invoke the supplied URI.
	 * <p>
	 * Uses the provided URI in the
	 * {@link org.springframework.security.web.util.matcher.RequestMatcher#matches(HttpServletRequest)}
	 * for every {@code RequestMatcher} configured. If no {@code RequestMatcher} is
	 * matched, or if there is not an available {@code WebInvocationPrivilegeEvaluator},
	 * returns {@code true}.
	 * @param uri the URI excluding the context path (a default context path setting will
	 * be used)
	 * @param contextPath the context path (may be null, in which case a default value
	 * will be used).
	 * @param method the HTTP method (or null, for any method)
	 * @param authentication the <tt>Authentication</tt> instance whose authorities should
	 * be used in evaluation whether access should be granted.
	 * @return true if access is allowed, false if denied
	 */
	@Override
	public boolean isAllowed(String contextPath, String uri, String method, Authentication authentication) {
		List<WebInvocationPrivilegeEvaluator> privilegeEvaluators = getDelegate(contextPath, uri, method);
		if (privilegeEvaluators.isEmpty()) {
			return true;
		}
		for (WebInvocationPrivilegeEvaluator evaluator : privilegeEvaluators) {
			boolean isAllowed = evaluator.isAllowed(contextPath, uri, method, authentication);
			if (!isAllowed) {
				return false;
			}
		}
		return true;
	}

	private List<WebInvocationPrivilegeEvaluator> getDelegate(String contextPath, String uri, String method) {
		FilterInvocation filterInvocation = new FilterInvocation(contextPath, uri, method, this.servletContext);
		for (RequestMatcherEntry<List<WebInvocationPrivilegeEvaluator>> delegate : this.delegates) {
			if (delegate.getRequestMatcher().matches(filterInvocation.getHttpRequest())) {
				return delegate.getEntry();
			}
		}
		return Collections.emptyList();
	}

	@Override
	public void setServletContext(ServletContext servletContext) {
		this.servletContext = servletContext;
	}

}
