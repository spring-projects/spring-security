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
 * Provides support for <a href="https://tools.ietf.org/html/rfc6797">HTTP Strict Transport
 * Security (HSTS)</a>.
 *
 * <p>
 * By default the expiration is one year, subdomains will be included and preload will not
 * be included. This can be customized using {@link #setMaxAgeInSeconds(long)},
 * {@link #setIncludeSubDomains(boolean)} and {@link #setPreload(boolean)}
 * respectively.
 * </p>
 *
 * <p>
 * Since <a href="https://tools.ietf.org/html/rfc6797#section-7.2">section 7.2</a> states
 * that HSTS Host MUST NOT include the STS header in HTTP responses, the default behavior
 * is that the "Strict-Transport-Security" will only be added when
 * {@link HttpServletRequest#isSecure()} returns {@code true} . At times this may need to
 * be customized. For example, in some situations where SSL termination is used, something
 * else may be used to determine if SSL was used. For these circumstances,
 * {@link #setRequestMatcher(RequestMatcher)} can be invoked with a custom
 * {@link RequestMatcher}.
 * </p>
 *
 * <p>
 * See <a href="https://hstspreload.org/">Website hstspreload.org</a>
 * for additional details on HSTS preload.
 * </p>
 *
 * @author Rob Winch
 * @author Ankur Pathak
 * @since 3.2
 */
public final class HstsHeaderWriter implements HeaderWriter {
	private static final long DEFAULT_MAX_AGE_SECONDS = 31536000;

	private static final String HSTS_HEADER_NAME = "Strict-Transport-Security";

	private final Log logger = LogFactory.getLog(getClass());

	private RequestMatcher requestMatcher;

	private long maxAgeInSeconds;

	private boolean includeSubDomains;

	private boolean preload;

	private String hstsHeaderValue;

	/**
	 * Creates a new instance
	 *
	 * @param requestMatcher maps to {@link #setRequestMatcher(RequestMatcher)}
	 * @param maxAgeInSeconds maps to {@link #setMaxAgeInSeconds(long)}
	 * @param includeSubDomains maps to {@link #setIncludeSubDomains(boolean)}
	 * @param preload maps to {@link #setPreload(boolean)}
	 * @since 5.2.0
	 * @author Ankur Pathak
	 */
	public HstsHeaderWriter(RequestMatcher requestMatcher, long maxAgeInSeconds,
			boolean includeSubDomains, boolean preload) {
		this.requestMatcher = requestMatcher;
		this.maxAgeInSeconds = maxAgeInSeconds;
		this.includeSubDomains = includeSubDomains;
		this.preload = preload;
		updateHstsHeaderValue();
	}

	/**
	 * Creates a new instance
	 *
	 * @param requestMatcher maps to {@link #setRequestMatcher(RequestMatcher)}
	 * @param maxAgeInSeconds maps to {@link #setMaxAgeInSeconds(long)}
	 * @param includeSubDomains maps to {@link #setIncludeSubDomains(boolean)}
	 */
	public HstsHeaderWriter(RequestMatcher requestMatcher, long maxAgeInSeconds,
			boolean includeSubDomains) {
		this(requestMatcher, maxAgeInSeconds, includeSubDomains, false);
	}

	/**
	 * Creates a new instance
	 *
	 * @param maxAgeInSeconds maps to {@link #setMaxAgeInSeconds(long)}
	 * @param includeSubDomains maps to {@link #setIncludeSubDomains(boolean)}
	 * @param preload maps to {@link #setPreload(boolean)}
	 * @since 5.2.0
	 * @author Ankur Pathak
	 */
	public HstsHeaderWriter(long maxAgeInSeconds, boolean includeSubDomains, boolean preload) {
		this(new SecureRequestMatcher(), maxAgeInSeconds, includeSubDomains, preload);
	}

	/**
	 * Creates a new instance
	 *
	 * @param maxAgeInSeconds maps to {@link #setMaxAgeInSeconds(long)}
	 * @param includeSubDomains maps to {@link #setIncludeSubDomains(boolean)}
	 */
	public HstsHeaderWriter(long maxAgeInSeconds, boolean includeSubDomains) {
		this(new SecureRequestMatcher(), maxAgeInSeconds, includeSubDomains, false);
	}

	/**
	 * Creates a new instance
	 *
	 * @param maxAgeInSeconds maps to {@link #setMaxAgeInSeconds(long)}
	 */
	public HstsHeaderWriter(long maxAgeInSeconds) {
		this(new SecureRequestMatcher(), maxAgeInSeconds, true, false);
	}

	/**
	 * Creates a new instance
	 *
	 * @param includeSubDomains maps to {@link #setIncludeSubDomains(boolean)}
	 */
	public HstsHeaderWriter(boolean includeSubDomains) {
		this(new SecureRequestMatcher(), DEFAULT_MAX_AGE_SECONDS, includeSubDomains, false);
	}

	/**
	 * Creates a new instance
	 */
	public HstsHeaderWriter() {
		this(DEFAULT_MAX_AGE_SECONDS);
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see org.springframework.security.web.headers.HeaderWriter#writeHeaders(javax
	 * .servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
	 */
	public void writeHeaders(HttpServletRequest request, HttpServletResponse response) {
		if (this.requestMatcher.matches(request)) {
			if (!response.containsHeader(HSTS_HEADER_NAME)) {
				response.setHeader(HSTS_HEADER_NAME, this.hstsHeaderValue);
			}
		}
		else if (this.logger.isDebugEnabled()) {
			this.logger
					.debug("Not injecting HSTS header since it did not match the requestMatcher "
							+ this.requestMatcher);
		}
	}

	/**
	 * Sets the {@link RequestMatcher} used to determine if the
	 * "Strict-Transport-Security" should be added. If true the header is added, else the
	 * header is not added. By default the header is added when
	 * {@link HttpServletRequest#isSecure()} returns true.
	 *
	 * @param requestMatcher the {@link RequestMatcher} to use.
	 * @throws IllegalArgumentException if {@link RequestMatcher} is null
	 */
	public void setRequestMatcher(RequestMatcher requestMatcher) {
		Assert.notNull(requestMatcher, "requestMatcher cannot be null");
		this.requestMatcher = requestMatcher;
	}

	/**
	 * <p>
	 * Sets the value (in seconds) for the max-age directive of the
	 * Strict-Transport-Security header. The default is one year.
	 * </p>
	 *
	 * <p>
	 * This instructs browsers how long to remember to keep this domain as a known HSTS
	 * Host. See <a href="https://tools.ietf.org/html/rfc6797#section-6.1.1">Section
	 * 6.1.1</a> for additional details.
	 * </p>
	 *
	 * @param maxAgeInSeconds the maximum amount of time (in seconds) to consider this
	 * domain as a known HSTS Host.
	 * @throws IllegalArgumentException if maxAgeInSeconds is negative
	 */
	public void setMaxAgeInSeconds(long maxAgeInSeconds) {
		if (maxAgeInSeconds < 0) {
			throw new IllegalArgumentException(
					"maxAgeInSeconds must be non-negative. Got " + maxAgeInSeconds);
		}
		this.maxAgeInSeconds = maxAgeInSeconds;
		updateHstsHeaderValue();
	}

	/**
	 * <p>
	 * If true, subdomains should be considered HSTS Hosts too. The default is true.
	 * </p>
	 *
	 * <p>
	 * See <a href="https://tools.ietf.org/html/rfc6797#section-6.1.2">Section 6.1.2</a>
	 * for additional details.
	 * </p>
	 *
	 * @param includeSubDomains true to include subdomains, else false
	 */
	public void setIncludeSubDomains(boolean includeSubDomains) {
		this.includeSubDomains = includeSubDomains;
		updateHstsHeaderValue();
	}
     /**
	 * <p>
	 * If true, preload will be included in HSTS Header. The default is false.
	 * </p>
	 *
	 * <p>
	 * See <a href="https://tools.ietf.org/html/rfc6797#section-6.1.2">Section 6.1.2</a>
	 * for additional details.
	 * </p>
	 *
	 * @param preload true to include preload, else false
     * @since 5.2.0
     * @autor Ankur Pathak
	 */
	public void setPreload(boolean preload) {
		this.preload = preload;
		updateHstsHeaderValue();
	}

	private void updateHstsHeaderValue() {
		String headerValue = "max-age=" + this.maxAgeInSeconds;
		if (this.includeSubDomains) {
			headerValue += " ; includeSubDomains";
		}
		if (this.preload) {
			headerValue += " ; preload";
		}
		this.hstsHeaderValue = headerValue;
	}

	private static final class SecureRequestMatcher implements RequestMatcher {
		public boolean matches(HttpServletRequest request) {
			return request.isSecure();
		}
	}
}
