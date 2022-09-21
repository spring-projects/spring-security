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

package org.springframework.security.web.csrf;

import java.io.IOException;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.event.RequestRejectedEvent;

/**
 * An {@link AccessDeniedHandler} that publishes a CSRF {@link RequestRejectedEvent}
 *
 * @author Josh Cummings
 * @since 6.0
 */
public final class CsrfRejectedEventPublishingAccessDeniedHandler
		implements AccessDeniedHandler, ApplicationEventPublisherAware {

	private ApplicationEventPublisher eventPublisher;

	/**
	 * Handles a CSRF-based access denied failure. Note that while the contract accepts an
	 * {@link AccessDeniedException}, only {@link CsrfException}s are published.
	 * @param request that resulted in an {@link AccessDeniedException}
	 * @param response so that the user agent can be advised of the failure
	 * @param exception that caused the invocation
	 * @throws IOException
	 * @throws ServletException
	 */
	@Override
	public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException exception)
			throws IOException, ServletException {
		if (this.eventPublisher == null) {
			return;
		}
		if (exception instanceof CsrfException) {
			this.eventPublisher.publishEvent(new RequestRejectedEvent<>(request, (CsrfException) exception));
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
		this.eventPublisher = applicationEventPublisher;
	}

}
