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

package org.springframework.security.web.context;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Used to pass the incoming request to
 * {@link SecurityContextRepository#loadContext(HttpRequestResponseHolder)}, allowing the
 * method to swap the request for a wrapped version, as well as returning the
 * <tt>SecurityContext</tt> value.
 *
 * @author Luke Taylor
 * @since 3.0
 * @deprecated Use
 * {@link SecurityContextRepository#loadDeferredContext(HttpServletRequest)}
 */
@Deprecated
public final class HttpRequestResponseHolder {

	private HttpServletRequest request;

	private HttpServletResponse response;

	public HttpRequestResponseHolder(HttpServletRequest request, HttpServletResponse response) {
		this.request = request;
		this.response = response;
	}

	public HttpServletRequest getRequest() {
		return this.request;
	}

	public void setRequest(HttpServletRequest request) {
		this.request = request;
	}

	public HttpServletResponse getResponse() {
		return this.response;
	}

	public void setResponse(HttpServletResponse response) {
		this.response = response;
	}

}
