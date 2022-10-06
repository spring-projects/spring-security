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

package org.springframework.security.web.header.writers;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.web.header.HeaderWriter;
import org.springframework.util.Assert;

/**
 * Renders the <a href=
 * "https://blogs.msdn.com/b/ieinternals/archive/2011/01/31/controlling-the-internet-explorer-xss-filter-with-the-x-xss-protection-http-header.aspx"
 * >X-XSS-Protection header</a>.
 *
 * @author Rob Winch
 * @author Ankur Pathak
 * @author Daniel Garnier-Moiroux
 * @since 3.2
 */
public final class XXssProtectionHeaderWriter implements HeaderWriter {

	private static final String XSS_PROTECTION_HEADER = "X-XSS-Protection";

	private HeaderValue headerValue;

	/**
	 * Create a new instance
	 */
	public XXssProtectionHeaderWriter() {
		this.headerValue = HeaderValue.DISABLED;
	}

	@Override
	public void writeHeaders(HttpServletRequest request, HttpServletResponse response) {
		if (!response.containsHeader(XSS_PROTECTION_HEADER)) {
			response.setHeader(XSS_PROTECTION_HEADER, this.headerValue.toString());
		}
	}

	/**
	 * Sets the value of the X-XSS-PROTECTION header.
	 * <p>
	 * If {@link HeaderValue#DISABLED}, will specify that X-XSS-Protection is disabled.
	 * For example:
	 *
	 * <pre>
	 * X-XSS-Protection: 0
	 * </pre>
	 * <p>
	 * If {@link HeaderValue#ENABLED}, will contain a value of 1, but will not specify the
	 * mode as blocked. In this instance, any content will be attempted to be fixed. For
	 * example:
	 *
	 * <pre>
	 * X-XSS-Protection: 1
	 * </pre>
	 * <p>
	 * If {@link HeaderValue#ENABLED_MODE_BLOCK}, will contain a value of 1 and will
	 * specify mode as blocked. The content will be replaced with "#". For example:
	 *
	 * <pre>
	 * X-XSS-Protection: 1 ; mode=block
	 * </pre>
	 * @param headerValue the new header value
	 * @throws IllegalArgumentException when headerValue is null
	 * @since 5.8
	 */
	public void setHeaderValue(HeaderValue headerValue) {
		Assert.notNull(headerValue, "headerValue cannot be null");
		this.headerValue = headerValue;
	}

	/**
	 * The value of the x-xss-protection header. One of: "0", "1", "1 ; mode=block"
	 *
	 * @author Daniel Garnier-Moiroux
	 * @since 5.8
	 */
	public enum HeaderValue {

		DISABLED("0"), ENABLED("1"), ENABLED_MODE_BLOCK("1; mode=block");

		private final String value;

		HeaderValue(String value) {
			this.value = value;
		}

		public static HeaderValue from(String headerValue) {
			for (HeaderValue value : values()) {
				if (value.toString().equals(headerValue)) {
					return value;
				}
			}
			return null;
		}

		@Override
		public String toString() {
			return this.value;
		}

	}

	@Override
	public String toString() {
		return getClass().getName() + " [headerValue=" + this.headerValue + "]";
	}

}
