/*
 * Copyright 2002-2019 the original author or authors.
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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.security.web.header.HeaderWriter;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

/**
 * Provides support for <a href="https://w3c.github.io/webappsec-clear-site-data/">Clear
 * Site Data</a>.
 *
 * <p>
 * Developers may instruct a user agent to clear various types of relevant data by
 * delivering a Clear-Site-Data HTTP response header in response to a request.
 * <p>
 *
 * <p>
 * Due to <a href="https://w3c.github.io/webappsec-clear-site-data/#incomplete">Incomplete
 * Clearing</a> section the header is only applied if the request is secure.
 * </p>
 *
 * @author Rafiullah Hamedy
 * @since 5.2
 */
public final class ClearSiteDataHeaderWriter implements HeaderWriter {

	private static final String CLEAR_SITE_DATA_HEADER = "Clear-Site-Data";

	private final Log logger = LogFactory.getLog(getClass());

	private final RequestMatcher requestMatcher;

	private String headerValue;

	/**
	 * <p>
	 * Creates a new instance of {@link ClearSiteDataHeaderWriter} with given sources. The
	 * constructor also initializes <b>requestMatcher</b> with a new instance of
	 * <b>SecureRequestMatcher</b> to ensure that header is only applied if and when the
	 * request is secure as per the <b>Incomplete Clearing</b> section.
	 * </p>
	 * @param directives (i.e. "cache", "cookies", "storage", "executionContexts" or "*")
	 * @throws IllegalArgumentException if sources is null or empty.
	 */
	public ClearSiteDataHeaderWriter(Directive... directives) {
		Assert.notEmpty(directives, "directives cannot be empty or null");
		this.requestMatcher = new SecureRequestMatcher();
		this.headerValue = transformToHeaderValue(directives);
	}

	@Override
	public void writeHeaders(HttpServletRequest request, HttpServletResponse response) {
		if (this.requestMatcher.matches(request)) {
			if (!response.containsHeader(CLEAR_SITE_DATA_HEADER)) {
				response.setHeader(CLEAR_SITE_DATA_HEADER, this.headerValue);
			}
		}
		else if (this.logger.isDebugEnabled()) {
			this.logger.debug("Not injecting Clear-Site-Data header since it did not match the " + "requestMatcher "
					+ this.requestMatcher);
		}
	}

	/**
	 * <p>
	 * Represents the directive values expected by the {@link ClearSiteDataHeaderWriter}
	 * </p>
	 * .
	 */
	public enum Directive {

		CACHE("cache"), COOKIES("cookies"), STORAGE("storage"), EXECUTION_CONTEXTS("executionContexts"), ALL("*");

		private final String headerValue;

		Directive(String headerValue) {
			this.headerValue = "\"" + headerValue + "\"";
		}

		public String getHeaderValue() {
			return this.headerValue;
		}

	}

	private String transformToHeaderValue(Directive... directives) {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < directives.length - 1; i++) {
			sb.append(directives[i].headerValue).append(", ");
		}
		sb.append(directives[directives.length - 1].headerValue);
		return sb.toString();
	}

	private static final class SecureRequestMatcher implements RequestMatcher {

		@Override
		public boolean matches(HttpServletRequest request) {
			return request.isSecure();
		}

	}

	@Override
	public String toString() {
		return getClass().getName() + " [headerValue=" + this.headerValue + "]";
	}

}
