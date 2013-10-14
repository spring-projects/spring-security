/*
 * Copyright 2002-2013 the original author or authors.
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
package org.springframework.security.web.header.writers;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.web.header.HeaderWriter;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

/**
 * Provides support for <a href="http://tools.ietf.org/html/rfc6797">HTTP Strict
 * Transport Security (HSTS)</a>.
 *
 * <p>
 * By default the expiration is one year and subdomains will be included. This
 * can be customized using {@link #setMaxAgeInSeconds(long)} and
 * {@link #setIncludeSubDomains(boolean)} respectively.
 * </p>
 *
 * <p>
 * Since <a href="http://tools.ietf.org/html/rfc6797#section-7.2">section
 * 7.2</a> states that HSTS Host MUST NOT include the STS header in HTTP
 * responses, the default behavior is that the "Strict-Transport-Security" will
 * only be added when {@link HttpServletRequest#isSecure()} returns {@code true}
 * . At times this may need to be customized. For example, in some situations
 * where SSL termination is used, something else may be used to determine if SSL
 * was used. For these circumstances, {@link #setRequestMatcher(RequestMatcher)}
 * can be invoked with a custom {@link RequestMatcher}.
 * </p>
 *
 * @author Rob Winch
 * @since 3.2
 */
public final class HstsHeaderWriter implements HeaderWriter {
    private static final long DEFAULT_MAX_AGE_SECONDS = 31536000;

    private static final String HSTS_HEADER_NAME = "Strict-Transport-Security";

    private final Log logger = LogFactory.getLog(getClass());

    private RequestMatcher requestMatcher;

    private long maxAgeInSeconds;

    private boolean includeSubDomains;

    private String hstsHeaderValue;

    /**
     * Creates a new instance
     *
     * @param requestMatcher maps to {@link #setRequestMatcher(RequestMatcher)}
     * @param maxAgeInSeconds maps to {@link #setMaxAgeInSeconds(long)}
     * @param includeSubDomains maps to {@link #setIncludeSubDomains(boolean)}
     */
    public HstsHeaderWriter(RequestMatcher requestMatcher,
            long maxAgeInSeconds, boolean includeSubDomains) {
        super();
        this.requestMatcher = requestMatcher;
        this.maxAgeInSeconds = maxAgeInSeconds;
        this.includeSubDomains = includeSubDomains;
        updateHstsHeaderValue();
    }

    /**
     * Creates a new instance
     *
     * @param maxAgeInSeconds maps to {@link #setMaxAgeInSeconds(long)}
     * @param includeSubDomains maps to {@link #setIncludeSubDomains(boolean)}
     */
    public HstsHeaderWriter(long maxAgeInSeconds, boolean includeSubDomains) {
        this(new SecureRequestMatcher(),maxAgeInSeconds,includeSubDomains);
    }

    /**
     * Creates a new instance
     *
     * @param maxAgeInSeconds maps to {@link #setMaxAgeInSeconds(long)}
     */
    public HstsHeaderWriter(long maxAgeInSeconds) {
        this(new SecureRequestMatcher(),maxAgeInSeconds,true);
    }

    /**
     * Creates a new instance
     *
     * @param includeSubDomains maps to {@link #setIncludeSubDomains(boolean)}
     */
    public HstsHeaderWriter(boolean includeSubDomains) {
        this(new SecureRequestMatcher(),DEFAULT_MAX_AGE_SECONDS,includeSubDomains);
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
     * @see
     * org.springframework.security.web.headers.HeaderWriter#writeHeaders(javax
     * .servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
     */
    public void writeHeaders(HttpServletRequest request,
            HttpServletResponse response) {
        if (requestMatcher.matches(request)) {
            response.setHeader(HSTS_HEADER_NAME, hstsHeaderValue);
        } else if (logger.isDebugEnabled()) {
            logger.debug("Not injecting HSTS header since it did not match the requestMatcher "
                    + requestMatcher);
        }
    }

    /**
     * Sets the {@link RequestMatcher} used to determine if the
     * "Strict-Transport-Security" should be added. If true the header is added,
     * else the header is not added. By default the header is added when
     * {@link HttpServletRequest#isSecure()} returns true.
     *
     * @param requestMatcher
     *            the {@link RequestMatcher} to use.
     * @throws IllegalArgumentException
     *             if {@link RequestMatcher} is null
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
     * This instructs browsers how long to remember to keep this domain as a
     * known HSTS Host. See <a
     * href="http://tools.ietf.org/html/rfc6797#section-6.1.1">Section 6.1.1</a>
     * for additional details.
     * </p>
     *
     * @param maxAgeInSeconds
     *            the maximum amount of time (in seconds) to consider this
     *            domain as a known HSTS Host.
     * @throws IllegalArgumentException
     *             if maxAgeInSeconds is negative
     */
    public void setMaxAgeInSeconds(long maxAgeInSeconds) {
        if (maxAgeInSeconds < 0) {
            throw new IllegalArgumentException(
                    "maxAgeInSeconds must be non-negative. Got "
                            + maxAgeInSeconds);
        }
        this.maxAgeInSeconds = maxAgeInSeconds;
        updateHstsHeaderValue();
    }

    /**
     * <p>
     * If true, subdomains should be considered HSTS Hosts too. The default is
     * true.
     * </p>
     *
     * <p>
     * See <a href="http://tools.ietf.org/html/rfc6797#section-6.1.2">Section
     * 6.1.2</a> for additional details.
     * </p>
     *
     * @param includeSubDomains
     *            true to include subdomains, else false
     */
    public void setIncludeSubDomains(boolean includeSubDomains) {
        this.includeSubDomains = includeSubDomains;
        updateHstsHeaderValue();
    }

    private void updateHstsHeaderValue() {
        String headerValue = "max-age=" + maxAgeInSeconds;
        if (includeSubDomains) {
            headerValue += " ; includeSubDomains";
        }
        this.hstsHeaderValue = headerValue;
    }

    private static final class SecureRequestMatcher implements RequestMatcher {
        public boolean matches(HttpServletRequest request) {
            return request.isSecure();
        }
    }
}
