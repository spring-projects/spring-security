/*
 * Copyright 2002-2019 the original author or authors.
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
package org.springframework.security.test.web.servlet.request;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.SecurityContextRepository;

/**
 * Used to wrap the SecurityContextRepository to provide support for testing in
 * stateless mode
 */
public class TestSecurityContextRepository implements SecurityContextRepository {
	private final static String ATTR_NAME = TestSecurityContextRepository.class
			.getName().concat(".REPO");

	private final SecurityContextRepository delegate;

	TestSecurityContextRepository(SecurityContextRepository delegate) {
		this.delegate = delegate;
	}

	@Override
	public SecurityContext loadContext(
			HttpRequestResponseHolder requestResponseHolder) {
		SecurityContext result = getContext(requestResponseHolder.getRequest());
		// always load from the delegate to ensure the request/response in the
		// holder are updated
		// remember the SecurityContextRepository is used in many different
		// locations
		SecurityContext delegateResult = this.delegate
				.loadContext(requestResponseHolder);
		return result == null ? delegateResult : result;
	}

	@Override
	public void saveContext(SecurityContext context, HttpServletRequest request,
			HttpServletResponse response) {
		request.setAttribute(ATTR_NAME, context);
		this.delegate.saveContext(context, request, response);
	}

	@Override
	public boolean containsContext(HttpServletRequest request) {
		return getContext(request) != null
				|| this.delegate.containsContext(request);
	}

	static SecurityContext getContext(HttpServletRequest request) {
		return (SecurityContext) request.getAttribute(ATTR_NAME);
	}
}