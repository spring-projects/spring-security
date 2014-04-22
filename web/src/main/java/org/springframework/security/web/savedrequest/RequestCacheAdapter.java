/*
 * Copyright 2002-2014 the original author or authors.
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
package org.springframework.security.web.savedrequest;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.util.Assert;

public class RequestCacheAdapter implements RequestCache {

    private final RequestCache delegate;

    public RequestCacheAdapter() {
        this(new HttpSessionRequestCache());
    }

    public RequestCacheAdapter(RequestCache delegate) {
        Assert.notNull(delegate, "delegate cannot be null");
        this.delegate = delegate;
    }

    public void saveRequest(HttpServletRequest request,
            HttpServletResponse response) {
        delegate.saveRequest(request, response);
    }

    public SavedRequest getRequest(HttpServletRequest request,
            HttpServletResponse response) {
        SavedRequest result = delegate.getRequest(request, response);
        Cookie[] cookies = request.getCookies();
        return new SavedRequestAdapter(result, cookies == null ? null : Arrays.asList(cookies));
    }

    public HttpServletRequest getMatchingRequest(HttpServletRequest request,
            HttpServletResponse response) {
        return delegate.getMatchingRequest(request, response);
    }

    public void removeRequest(HttpServletRequest request,
            HttpServletResponse response) {
        delegate.removeRequest(request, response);
    }

    private static class SavedRequestAdapter implements SavedRequest {
        private SavedRequest delegate;
        private List<Cookie> cookies;

        public SavedRequestAdapter(SavedRequest delegate, List<Cookie> cookies) {
            this.delegate = delegate;
            this.cookies = cookies;
        }

        public String getRedirectUrl() {
            return delegate.getRedirectUrl();
        }

        public List<Cookie> getCookies() {
            return cookies;
        }

        public String getMethod() {
            return delegate.getMethod();
        }

        public List<String> getHeaderValues(String name) {
            return delegate.getHeaderValues(name);
        }

        public Collection<String> getHeaderNames() {
            return delegate.getHeaderNames();
        }

        public List<Locale> getLocales() {
            return delegate.getLocales();
        }

        public String[] getParameterValues(String name) {
            return delegate.getParameterValues(name);
        }

        public Map<String, String[]> getParameterMap() {
            return delegate.getParameterMap();
        }

        private static final long serialVersionUID = 1184951442151447331L;
    }
}
