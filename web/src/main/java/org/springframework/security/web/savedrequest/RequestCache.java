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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Implements "saved request" logic, allowing a single request to be retrieved and
 * restarted after redirecting to an authentication mechanism.
 *
 * @author Luke Taylor
 * @since 3.0
 */
public interface RequestCache {

	/**
	 * Caches the current request for later retrieval, once authentication has taken
	 * place. Used by <tt>ExceptionTranslationFilter</tt>.
	 * @param request the request to be stored
	 */
	void saveRequest(HttpServletRequest request, HttpServletResponse response);

	/**
	 * Returns the saved request, leaving it cached.
	 * @param request the current request
	 * @return the saved request which was previously cached, or null if there is none.
	 */
	SavedRequest getRequest(HttpServletRequest request, HttpServletResponse response);

	/**
	 * Returns a wrapper around the saved request, if it matches the current request. The
	 * saved request should be removed from the cache.
	 * @param request
	 * @param response
	 * @return the wrapped save request, if it matches the original, or null if there is
	 * no cached request or it doesn't match.
	 */
	HttpServletRequest getMatchingRequest(HttpServletRequest request, HttpServletResponse response);

	/**
	 * Removes the cached request.
	 * @param request the current request, allowing access to the cache.
	 */
	void removeRequest(HttpServletRequest request, HttpServletResponse response);

}
