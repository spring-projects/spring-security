/*
 * Copyright 2002-2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.web.util.matcher;

import javax.servlet.http.HttpServletRequest;

/**
 * Decides whether the Request Originated from Javascript.
 *
 * @author Shazin Sadakath
 */
public class JavascriptOriginRequestMatcher implements RequestMatcher {

	public static final String HTTP_X_REQUESTED_WITH = "HTTP_X_REQUESTED_WITH";
	public static final String XML_HTTP_REQUEST = "XMLHttpRequest";

	private String headerName = HTTP_X_REQUESTED_WITH;
	private String headerValue = XML_HTTP_REQUEST;


	@Override
	public boolean matches(HttpServletRequest request) {
		Object xHttpRequestedWith = request.getHeader(headerName);
		return xHttpRequestedWith != null && xHttpRequestedWith.toString().equalsIgnoreCase(headerValue);
	}

	public String getHeaderName() {
		return headerName;
	}

	public void setHeaderName(String headerName) {
		this.headerName = headerName;
	}

	public String getHeaderValue() {
		return headerValue;
	}

	public void setHeaderValue(String headerValue) {
		this.headerValue = headerValue;
	}
}
