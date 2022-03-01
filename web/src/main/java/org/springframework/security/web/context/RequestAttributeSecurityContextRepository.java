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

package org.springframework.security.web.context;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Stores the {@link SecurityContext} on a
 * {@link javax.servlet.ServletRequest#setAttribute(String, Object)} so that it can be
 * restored when different dispatch types occur. It will not be available on subsequent
 * requests.
 *
 * Unlike {@link HttpSessionSecurityContextRepository} this filter has no need to persist
 * the {@link SecurityContext} on the response being committed because the
 * {@link SecurityContext} will not be available for subsequent requests for
 * {@link RequestAttributeSecurityContextRepository}.
 *
 * @author Rob Winch
 * @since 5.7
 */
public final class RequestAttributeSecurityContextRepository implements SecurityContextRepository {

	/**
	 * The default request attribute name to use.
	 */
	public static final String DEFAULT_REQUEST_ATTR_NAME = RequestAttributeSecurityContextRepository.class.getName()
			.concat(".SPRING_SECURITY_CONTEXT");

	private final String requestAttributeName;

	/**
	 * Creates a new instance using {@link #DEFAULT_REQUEST_ATTR_NAME}.
	 */
	public RequestAttributeSecurityContextRepository() {
		this(DEFAULT_REQUEST_ATTR_NAME);
	}

	/**
	 * Creates a new instance with the specified request attribute name.
	 * @param requestAttributeName the request attribute name to set to the
	 * {@link SecurityContext}.
	 */
	public RequestAttributeSecurityContextRepository(String requestAttributeName) {
		this.requestAttributeName = requestAttributeName;
	}

	@Override
	public boolean containsContext(HttpServletRequest request) {
		return loadContext(request) != null;
	}

	@Override
	public SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder) {
		SecurityContext context = loadContext(requestResponseHolder.getRequest());
		return (context != null) ? context : SecurityContextHolder.createEmptyContext();
	}

	private SecurityContext loadContext(HttpServletRequest request) {
		return (SecurityContext) request.getAttribute(this.requestAttributeName);
	}

	@Override
	public void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response) {
		request.setAttribute(this.requestAttributeName, context);
	}

}
