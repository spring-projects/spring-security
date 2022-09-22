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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * A callback interface that is used to determine the {@link CsrfToken} to use and make
 * the {@link CsrfToken} available as a request attribute. Implementations of this
 * interface may choose to perform additional tasks or customize how the token is made
 * available to the application through request attributes.
 *
 * @author Steve Riesenberg
 * @since 5.8
 * @see CsrfTokenRequestProcessor
 */
@FunctionalInterface
public interface CsrfTokenRequestHandler {

	/**
	 * Handles a request using a {@link CsrfToken}.
	 * @param request the {@code HttpServletRequest} being handled
	 * @param response the {@code HttpServletResponse} being handled
	 */
	DeferredCsrfToken handle(HttpServletRequest request, HttpServletResponse response);

}
