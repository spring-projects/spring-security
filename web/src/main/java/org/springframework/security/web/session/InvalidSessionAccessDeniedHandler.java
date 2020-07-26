/*
 * Copyright 2002-2013 the original author or authors.
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

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.util.Assert;

/**
 * An adapter of {@link InvalidSessionStrategy} to {@link AccessDeniedHandler}
 *
 * @author Rob Winch
 * @since 3.2
 */
public final class InvalidSessionAccessDeniedHandler implements AccessDeniedHandler {

	private final InvalidSessionStrategy invalidSessionStrategy;

	/**
	 * Creates a new instance
	 * @param invalidSessionStrategy the {@link InvalidSessionStrategy} to delegate to
	 */
	public InvalidSessionAccessDeniedHandler(InvalidSessionStrategy invalidSessionStrategy) {
		Assert.notNull(invalidSessionStrategy, "invalidSessionStrategy cannot be null");
		this.invalidSessionStrategy = invalidSessionStrategy;
	}

	public void handle(HttpServletRequest request, HttpServletResponse response,
			AccessDeniedException accessDeniedException) throws IOException, ServletException {
		this.invalidSessionStrategy.onInvalidSessionDetected(request, response);
	}

}