/*
 * Copyright 2002-2014 the original author or authors.
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

import org.springframework.util.Assert;

/**
 * A {@link RequestMatcher} that can be used to match request that contain a header with
 * an expected header name and an expected value.
 *
 * <p>
 * For example, the following will match an request that contains a header with the name
 * X-Requested-With no matter what the value is.
 * </p>
 *
 * <pre>
 * RequestMatcher matcher = new RequestHeaderRequestMatcher(&quot;X-Requested-With&quot;);
 * </pre>
 *
 * Alternatively, the RequestHeaderRequestMatcher can be more precise and require a
 * specific value. For example the following will match on requests with the header name
 * of X-Requested-With with the value of "XMLHttpRequest", but will not match on header
 * name of "X-Requested-With" with the value of "Other".
 *
 * <pre>
 * RequestMatcher matcher = new RequestHeaderRequestMatcher(&quot;X-Requested-With&quot;,
 * 		&quot;XMLHttpRequest&quot;);
 * </pre>
 *
 * The value used to compare is the first header value, so in the previous example if the
 * header "X-Requested-With" contains the values "Other" and "XMLHttpRequest", then it
 * will not match.
 *
 * @author Rob Winch
 * @since 3.2
 */
public final class RequestHeaderRequestMatcher extends AbstractRequestMatcher {
	private final String expectedHeaderName;
	private final String expectedHeaderValue;

	/**
	 * Creates a new instance that will match if a header by the name of
	 * {@link #expectedHeaderName} is present. In this instance, the value does not
	 * matter.
	 *
	 * @param expectedHeaderName the name of the expected header that if present the
	 * request will match. Cannot be null.
	 */
	public RequestHeaderRequestMatcher(String expectedHeaderName) {
		this(expectedHeaderName, null);
	}

	/**
	 * Creates a new instance that will match if a header by the name of
	 * {@link #expectedHeaderName} is present and if the {@link #expectedHeaderValue} is
	 * non-null the first value is the same.
	 *
	 * @param expectedHeaderName the name of the expected header. Cannot be null
	 * @param expectedHeaderValue the expected header value or null if the value does not
	 * matter
	 */
	public RequestHeaderRequestMatcher(String expectedHeaderName,
			String expectedHeaderValue) {
		Assert.notNull(expectedHeaderName, "headerName cannot be null");
		this.expectedHeaderName = expectedHeaderName;
		this.expectedHeaderValue = expectedHeaderValue;
	}

	public boolean matches(HttpServletRequest request) {
		String actualHeaderValue = request.getHeader(expectedHeaderName);
		if (expectedHeaderValue == null) {
			return actualHeaderValue != null;
		}

		return expectedHeaderValue.equals(actualHeaderValue);
	}

	@Override
	public String toString() {
		return "RequestHeaderRequestMatcher [expectedHeaderName=" + expectedHeaderName
				+ ", expectedHeaderValue=" + expectedHeaderValue + ", id=" + getId() + "]";
	}
}
