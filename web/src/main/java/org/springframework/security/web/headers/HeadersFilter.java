/*
 * Copyright 2002-2012 the original author or authors.
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
package org.springframework.security.web.headers;

import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;

/**
 * Filter implementation to add headers to the current request. Can be useful to add certain headers which enable
 * browser protection. Like X-Frame-Options, X-XSS-Protection and X-Content-Type-Options.
 *
 * @author Marten Deinum
 * @since 3.2
 *
 */
public class HeadersFilter extends OncePerRequestFilter {

    /** Collection of {@link HeaderWriter} instances to  write out the headers to the response . */
    private final List<HeaderWriter> headerWriters;

    /**
     * Creates a new instance.
     *
     * @param headerWriters the {@link HeaderWriter} instances to write out headers to the {@link HttpServletResponse}.
     */
    public HeadersFilter(List<HeaderWriter> headerWriters) {
        Assert.notEmpty(headerWriters, "headerWriters cannot be null");
        this.headerWriters = headerWriters;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        for (HeaderWriter factory : headerWriters) {
            factory.writeHeaders(request, response);
        }
        filterChain.doFilter(request, response);
    }

}
