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

package org.springframework.security.web.session;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.context.ApplicationEvent;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.util.Assert;

/**
 * An event for when a {@link SessionInformation} is expired.
 *
 * @author Rob Winch
 * @since 4.2
 */
@SuppressWarnings("serial")
public final class SessionInformationExpiredEvent extends ApplicationEvent {

	private final HttpServletRequest request;

	private final HttpServletResponse response;

	private final FilterChain filterChain;

	/**
	 * Creates a new instance
	 * @param sessionInformation the SessionInformation that is expired
	 * @param request the HttpServletRequest
	 * @param response the HttpServletResponse
	 */
	public SessionInformationExpiredEvent(SessionInformation sessionInformation, HttpServletRequest request,
			HttpServletResponse response) {
		this(sessionInformation, request, response, null);
	}

	/**
	 * Creates a new instance
	 * @param sessionInformation the SessionInformation that is expired
	 * @param request the HttpServletRequest
	 * @param response the HttpServletResponse
	 * @param filterChain the FilterChain
	 * @since 6.4
	 */
	public SessionInformationExpiredEvent(SessionInformation sessionInformation, HttpServletRequest request,
			HttpServletResponse response, FilterChain filterChain) {
		super(sessionInformation);
		Assert.notNull(request, "request cannot be null");
		Assert.notNull(response, "response cannot be null");
		this.request = request;
		this.response = response;
		this.filterChain = filterChain;
	}

	/**
	 * @return the request
	 */
	public HttpServletRequest getRequest() {
		return this.request;
	}

	/**
	 * @return the response
	 */
	public HttpServletResponse getResponse() {
		return this.response;
	}

	public SessionInformation getSessionInformation() {
		return (SessionInformation) getSource();
	}

	/**
	 * @return the filter chain. Can be {@code null}.
	 * @since 6.4
	 */
	public FilterChain getFilterChain() {
		return this.filterChain;
	}

}
