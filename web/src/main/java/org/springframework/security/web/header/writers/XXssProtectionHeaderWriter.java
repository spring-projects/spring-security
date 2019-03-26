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
package org.springframework.security.web.header.writers;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.web.header.HeaderWriter;

/**
 * Renders the <a href=
 * "https://blogs.msdn.com/b/ieinternals/archive/2011/01/31/controlling-the-internet-explorer-xss-filter-with-the-x-xss-protection-http-header.aspx"
 * >X-XSS-Protection header</a>.
 *
 * @author Rob Winch
 * @since 3.2
 */
public final class XXssProtectionHeaderWriter implements HeaderWriter {
	private static final String XSS_PROTECTION_HEADER = "X-XSS-Protection";

	private boolean enabled;

	private boolean block;

	private String headerValue;

	/**
	 * Create a new instance
	 */
	public XXssProtectionHeaderWriter() {
		this.enabled = true;
		this.block = true;
		updateHeaderValue();
	}

	public void writeHeaders(HttpServletRequest request, HttpServletResponse response) {
		response.setHeader(XSS_PROTECTION_HEADER, headerValue);
	}

	/**
	 * If true, will contain a value of 1. For example:
	 *
	 * <pre>
	 * X-XSS-Protection: 1
	 * </pre>
	 *
	 * or if {@link #setBlock(boolean)} is true
	 *
	 *
	 * <pre>
	 * X-XSS-Protection: 1; mode=block
	 * </pre>
	 *
	 * If false, will explicitly disable specify that X-XSS-Protection is disabled. For
	 * example:
	 *
	 * <pre>
	 * X-XSS-Protection: 0
	 * </pre>
	 *
	 * @param enabled the new value
	 */
	public void setEnabled(boolean enabled) {
		if (!enabled) {
			setBlock(false);
		}
		this.enabled = enabled;
		updateHeaderValue();
	}

	/**
	 * If false, will not specify the mode as blocked. In this instance, any content will
	 * be attempted to be fixed. If true, the content will be replaced with "#".
	 *
	 * @param block the new value
	 */
	public void setBlock(boolean block) {
		if (!enabled && block) {
			throw new IllegalArgumentException(
					"Cannot set block to true with enabled false");
		}
		this.block = block;
		updateHeaderValue();
	}

	private void updateHeaderValue() {
		if (!enabled) {
			this.headerValue = "0";
			return;
		}
		this.headerValue = "1";
		if (block) {
			this.headerValue += "; mode=block";
		}
	}

	@Override
	public String toString() {
		return getClass().getName() + " [headerValue=" + headerValue + "]";
	}
}
