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

import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * Filter implementation to add headers to the current request. Can be useful to add certain headers which enable
 * browser protection. Like X-Frame-Options, X-XSS-Protection and X-Content-Type-Options.
 *
 * @author Marten Deinum
 * @since 3.2
 *
 */
public class HeadersFilter extends OncePerRequestFilter {

    /** Map of headers to add to a response */
    private final Map<String, String> headers = new HashMap<String, String>();

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        for (Map.Entry<String, String> header : headers.entrySet()) {
            String name = header.getKey();
            String value = header.getValue();
            if (logger.isTraceEnabled()) {
                logger.trace("Adding header '" + name + "' with value '"+value +"'");
            }
            response.setHeader(header.getKey(), header.getValue());
        }
        filterChain.doFilter(request, response);
    }

    public void setHeaders(Map<String, String> headers) {
        this.headers.clear();
        this.headers.putAll(headers);
    }

    public void addHeader(String name, String value) {
        headers.put(name, value);
    }
}
