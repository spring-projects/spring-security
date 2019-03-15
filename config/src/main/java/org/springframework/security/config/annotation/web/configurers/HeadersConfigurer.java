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
package org.springframework.security.config.annotation.web.configurers;

import java.util.ArrayList;
import java.util.List;

import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.header.HeaderWriter;
import org.springframework.security.web.header.HeaderWriterFilter;
import org.springframework.security.web.header.writers.CacheControlHeadersWriter;
import org.springframework.security.web.header.writers.HstsHeaderWriter;
import org.springframework.security.web.header.writers.XContentTypeOptionsHeaderWriter;
import org.springframework.security.web.header.writers.XXssProtectionHeaderWriter;
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter;
import org.springframework.util.Assert;

/**
 * Adds the Security headers to the response. This is activated by default when
 * using {@link WebSecurityConfigurerAdapter}'s default constructor. Only
 * invoking the {@link #headers()} without invoking additional methods on it, or
 * accepting the default provided by {@link WebSecurityConfigurerAdapter}, is
 * the equivalent of:
 *
 * <pre>
 * &#064;Configuration
 * &#064;EnableWebSecurity
 * public class CsrfSecurityConfig extends WebSecurityConfigurerAdapter {
 *
 * 	&#064;Override
 *     protected void configure(HttpSecurity http) throws Exception {
 *         http
 *             .headers()
 *                 .contentTypeOptions();
 *                 .xssProtection()
 *                 .cacheControl()
 *                 .httpStrictTransportSecurity()
 *                 .frameOptions()
 *                 .and()
 *             ...;
 *     }
 * }
 * </pre>
 *
 * You can disable the headers using the following:
 *
 * <pre>
 * &#064;Configuration
 * &#064;EnableWebSecurity
 * public class CsrfSecurityConfig extends WebSecurityConfigurerAdapter {
 *
 * 	&#064;Override
 *     protected void configure(HttpSecurity http) throws Exception {
 *         http
 *             .headers().disable()
 *             ...;
 *     }
 * }
 * </pre>
 *
 * You can enable only a few of the headers by invoking the appropriate methods
 * on {@link #headers()} result. For example, the following will enable
 * {@link HeadersConfigurer#cacheControl()} and
 * {@link HeadersConfigurer#frameOptions()} only.
 *
 * <pre>
 * &#064;Configuration
 * &#064;EnableWebSecurity
 * public class CsrfSecurityConfig extends WebSecurityConfigurerAdapter {
 *
 * 	&#064;Override
 *     protected void configure(HttpSecurity http) throws Exception {
 *         http
 *             .headers()
 *                 .cacheControl()
 *                 .frameOptions()
 *                 .and()
 *             ...;
 *     }
 * }
 * </pre>
 *
 * @author Rob Winch
 * @since 3.2
 */
public final class HeadersConfigurer<H extends HttpSecurityBuilder<H>> extends
        AbstractHttpConfigurer<HeadersConfigurer<H>, H> {
    private List<HeaderWriter> headerWriters = new ArrayList<HeaderWriter>();

    /**
     * Creates a new instance
     *
     * @see HttpSecurity#headers()
     */
    public HeadersConfigurer() {
    }

    /**
     * Adds a {@link HeaderWriter} instance
     *
     * @param headerWriter
     *            the {@link HeaderWriter} instance to add
     * @return the {@link HeadersConfigurer} for additional customizations
     */
    public HeadersConfigurer<H> addHeaderWriter(HeaderWriter headerWriter) {
        Assert.notNull(headerWriter, "headerWriter cannot be null");
        this.headerWriters.add(headerWriter);
        return this;
    }

    /**
     * Adds {@link XContentTypeOptionsHeaderWriter} which inserts the <a href=
     * "http://msdn.microsoft.com/en-us/library/ie/gg622941(v=vs.85).aspx"
     * >X-Content-Type-Options</a>:
     *
     * <pre>
     * X-Content-Type-Options: nosniff
     * </pre>
     *
     * @return the {@link HeadersConfigurer} for additional customizations
     */
    public HeadersConfigurer<H> contentTypeOptions() {
        return addHeaderWriter(new XContentTypeOptionsHeaderWriter());
    }

    /**
     * <strong>Note this is not comprehensive XSS protection!</strong>
     *
     * <para>Adds {@link XXssProtectionHeaderWriter} which adds the <a href=
     * "http://blogs.msdn.com/b/ieinternals/archive/2011/01/31/controlling-the-internet-explorer-xss-filter-with-the-x-xss-protection-http-header.aspx"
     * >X-XSS-Protection header</a>
     *
     * @return the {@link HeadersConfigurer} for additional customizations
     */
    public HeadersConfigurer<H> xssProtection() {
        return addHeaderWriter(new XXssProtectionHeaderWriter());
    }

    /**
     * Adds {@link CacheControlHeadersWriter}. Specifically it adds the
     * following headers:
     * <ul>
     * <li>Cache-Control: no-cache, no-store, max-age=0, must-revalidate</li>
     * <li>Pragma: no-cache</li>
     * <li>Expires: 0</li>
     * </ul>
     *
     * @return the {@link HeadersConfigurer} for additional customizations
     */
    public HeadersConfigurer<H> cacheControl() {
        return addHeaderWriter(new CacheControlHeadersWriter());
    }

    /**
     * Adds {@link HstsHeaderWriter} which provides support for <a
     * href="http://tools.ietf.org/html/rfc6797">HTTP Strict Transport Security
     * (HSTS)</a>.
     *
     * <p>
     * For additional configuration options, use
     * {@link #addHeaderWriter(HeaderWriter)} and {@link HstsHeaderWriter}
     * directly.
     * </p>
     *
     * @return the {@link HeadersConfigurer} for additional customizations
     */
    public HeadersConfigurer<H> httpStrictTransportSecurity() {
        return addHeaderWriter(new HstsHeaderWriter());
    }

    /**
     * Adds {@link XFrameOptionsHeaderWriter} with all the default settings. For
     * additional configuration options, use
     * {@link #addHeaderWriter(HeaderWriter)} and
     * {@link XFrameOptionsHeaderWriter} directly.
     *
     * @return the {@link HeadersConfigurer} for additional customizations
     */
    public HeadersConfigurer<H> frameOptions() {
        return addHeaderWriter(new XFrameOptionsHeaderWriter());
    }

    @Override
    public void configure(H http) throws Exception {
        HeaderWriterFilter headersFilter = createHeaderWriterFilter();
        http.addFilter(headersFilter);
    }

    /**
     * Creates the {@link HeaderWriter}
     *
     * @return the {@link HeaderWriter}
     */
    private HeaderWriterFilter createHeaderWriterFilter() {
        HeaderWriterFilter headersFilter = new HeaderWriterFilter(
                getHeaderWriters());
        headersFilter = postProcess(headersFilter);
        return headersFilter;
    }

    /**
     * Gets the {@link HeaderWriter} instances and possibly initializes with the
     * defaults.
     *
     * @return
     */
    private List<HeaderWriter> getHeaderWriters() {
        if (headerWriters.isEmpty()) {
            addDefaultHeaderWriters();
        }
        return headerWriters;
    }

    /**
     * Explicitly adds the default {@link HeaderWriter} instances. If no,
     * {@link HeaderWriter} instances have been added this is automatically
     * invoked.
     *
     */
    private void addDefaultHeaderWriters() {
        contentTypeOptions();
        xssProtection();
        cacheControl();
        httpStrictTransportSecurity();
        frameOptions();
    }
}