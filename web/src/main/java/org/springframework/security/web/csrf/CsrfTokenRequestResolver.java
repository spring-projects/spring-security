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

import jakarta.servlet.http.HttpServletRequest;

/**
 * Implementations of this interface are capable of resolving the token value of a
 * {@link CsrfToken} from the provided {@code HttpServletRequest}. Used by the
 * {@link CsrfFilter}.
 *
 * @author Steve Riesenberg
 * @since 5.8
 * @see CsrfTokenRequestAttributeHandler
 */
@FunctionalInterface
public interface CsrfTokenRequestResolver {

	/**
	 * Returns the token value resolved from the provided {@code HttpServletRequest} and
	 * {@link CsrfToken} or {@code null} if not available.
	 * @param request the {@code HttpServletRequest} being processed
	 * @param csrfToken the {@link CsrfToken} created by the {@link CsrfTokenRepository}
	 * @return the token value resolved from the request
	 */
	String resolveCsrfTokenValue(HttpServletRequest request, CsrfToken csrfToken);

}
