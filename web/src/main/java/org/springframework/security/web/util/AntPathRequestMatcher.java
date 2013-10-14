/*
 * Copyright 2002-2012 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.springframework.security.web.util;

import javax.servlet.http.HttpServletRequest;

import org.springframework.util.AntPathMatcher;

/**
 * Matcher which compares a pre-defined ant-style pattern against the URL
 * ({@code servletPath + pathInfo}) of an {@code HttpServletRequest}.
 * The query string of the URL is ignored and matching is case-insensitive or case-sensitive depending on
 * the arguments passed into the constructor.
 * <p>
 * Using a pattern value of {@code /**} or {@code **} is treated as a universal
 * match, which will match any request. Patterns which end with {@code /**} (and have no other wildcards)
 * are optimized by using a substring match &mdash; a pattern of {@code /aaa/**} will match {@code /aaa},
 * {@code /aaa/} and any sub-directories, such as {@code /aaa/bbb/ccc}.
 * </p>
 * <p>
 * For all other cases, Spring's {@link AntPathMatcher} is used to perform the match. See the Spring documentation
 * for this class for comprehensive information on the syntax used.
 * </p>
 *
 * @author Luke Taylor
 * @author Rob Winch
 * @since 3.1
 * @deprecated use {@link org.springframework.security.web.util.matchers.AntPathRequestMatcher}
 * @see org.springframework.util.AntPathMatcher
 */
public final class AntPathRequestMatcher implements RequestMatcher {
    private final org.springframework.security.web.util.matchers.AntPathRequestMatcher delegate;

    /**
     * Creates a matcher with the specific pattern which will match all HTTP
     * methods in a case insensitive manner.
     *
     * @param pattern
     *            the ant pattern to use for matching
     */
    public AntPathRequestMatcher(String pattern) {
        this(pattern, null);
    }

    /**
     * Creates a matcher with the supplied pattern and HTTP method in a case
     * insensitive manner.
     *
     * @param pattern
     *            the ant pattern to use for matching
     * @param httpMethod
     *            the HTTP method. The {@code matches} method will return false
     *            if the incoming request doesn't have the same method.
     */
    public AntPathRequestMatcher(String pattern, String httpMethod) {
        this(pattern,httpMethod,false);
    }

    /**
     * Creates a matcher with the supplied pattern which will match the
     * specified Http method
     *
     * @param pattern
     *            the ant pattern to use for matching
     * @param httpMethod
     *            the HTTP method. The {@code matches} method will return false
     *            if the incoming request doesn't doesn't have the same method.
     * @param caseSensitive
     *            true if the matcher should consider case, else false
     */
    public AntPathRequestMatcher(String pattern, String httpMethod, boolean caseSensitive) {
        this.delegate = new org.springframework.security.web.util.matchers.AntPathRequestMatcher(pattern, httpMethod, caseSensitive);
    }

    /**
     * Returns true if the configured pattern (and HTTP-Method) match those of the supplied request.
     *
     * @param request the request to match against. The ant pattern will be matched against the
     *    {@code servletPath} + {@code pathInfo} of the request.
     */
    public boolean matches(HttpServletRequest request) {
        return this.delegate.matches(request);
    }

    public org.springframework.security.web.util.matchers.AntPathRequestMatcher getDelegate() {
        return delegate;
    }

    public String getPattern() {
        return delegate.getPattern();
    }

    @Override
    public boolean equals(Object obj) {
        return delegate.equals(obj);
    }

    @Override
    public int hashCode() {
        return delegate.hashCode();
    }

    @Override
    public String toString() {
        return delegate.toString();
    }
}
