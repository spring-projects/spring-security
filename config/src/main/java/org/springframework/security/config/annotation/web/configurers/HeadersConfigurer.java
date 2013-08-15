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
package org.springframework.security.config.annotation.web.configurers;

import java.util.ArrayList;
import java.util.List;

import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.header.HeaderWriter;
import org.springframework.security.web.header.HeaderWriterFilter;
import org.springframework.security.web.header.writers.CacheControlHeadersWriter;
import org.springframework.security.web.header.writers.HstsHeaderWriter;
import org.springframework.security.web.header.writers.XContentTypeOptionsHeaderWriter;
import org.springframework.security.web.header.writers.XXssProtectionHeaderWriter;
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter;
import org.springframework.util.Assert;

import com.sun.xml.internal.ws.api.ha.StickyFeature;

/**
 * @author Rob Winch
 * @since 3.2
 * @see RememberMeConfigurer
 */
public final class HeadersConfigurer<H extends HttpSecurityBuilder<H>> extends AbstractHttpConfigurer<H> {
    private List<HeaderWriter> headerWriters = new ArrayList<HeaderWriter>();

    /**
     * Creates a new instance
     * @see HttpSecurity#headers()
     */
    public HeadersConfigurer() {
    }

    /**
     * Adds a {@link HeaderWriter} instance
     * @param headerWriter the {@link HeaderWriter} instance to add
     * @return the {@link HeadersConfigurer} for additional customizations
     */
    public HeadersConfigurer<H> addHeaderWriter(HeaderWriter headerWriter) {
        Assert.notNull(headerWriter, "headerWriter cannot be null");
        this.headerWriters.add(headerWriter);
        return this;
    }

    /**
     * Adds {@link XContentTypeOptionsHeaderWriter}
     *
     * @return the {@link HeadersConfigurer} for additional customizations
     */
    public HeadersConfigurer<H> contentTypeOptions() {
        return addHeaderWriter(new XContentTypeOptionsHeaderWriter());
    }

    /**
     * Adds {@link XXssProtectionHeaderWriter}. Note this is not comprehensive
     * XSS protection!
     *
     * @return the {@link HeadersConfigurer} for additional customizations
     */
    public HeadersConfigurer<H> xssProtection() {
        return addHeaderWriter(new XContentTypeOptionsHeaderWriter());
    }

    /**
     * Adds {@link CacheControlHeadersWriter}.
     *
     * @return the {@link HeadersConfigurer} for additional customizations
     */
    public HeadersConfigurer<H> cacheControl() {
        return addHeaderWriter(new CacheControlHeadersWriter());
    }

    /**
     * Adds {@link HstsHeaderWriter}.
     *
     * @return the {@link HeadersConfigurer} for additional customizations
     */
    public HeadersConfigurer<H> httpStrictTransportSecurity() {
        return addHeaderWriter(new HstsHeaderWriter());
    }

    /**
     * Adds {@link XFrameOptionsHeaderWriter} with all the default settings.
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
     * @return the {@link HeaderWriter}
     */
    private HeaderWriterFilter createHeaderWriterFilter() {
        HeaderWriterFilter headersFilter = new HeaderWriterFilter(getHeaderWriters());
        headersFilter = postProcess(headersFilter);
        return headersFilter;
    }

    /**
     * Gets the {@link HeaderWriter} instances and possibly initializes with the defaults.
     * @return
     */
    private List<HeaderWriter> getHeaderWriters() {
        if(headerWriters.isEmpty()) {
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