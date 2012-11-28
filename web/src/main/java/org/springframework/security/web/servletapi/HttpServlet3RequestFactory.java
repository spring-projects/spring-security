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
package org.springframework.security.web.servletapi;

import javax.servlet.AsyncContext;
import javax.servlet.AsyncListener;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.springframework.security.concurrent.DelegatingSecurityContextRunnable;

final class HttpServlet3RequestFactory implements HttpServletRequestFactory {
    private final String rolePrefix;

    HttpServlet3RequestFactory(String rolePrefix) {
        this.rolePrefix = rolePrefix;
    }

    public HttpServletRequest create(HttpServletRequest request) {
        return new Servlet3SecurityContextHolderAwareRequestWrapper(request, rolePrefix);
    }

    private static class Servlet3SecurityContextHolderAwareRequestWrapper extends SecurityContextHolderAwareRequestWrapper {
        public Servlet3SecurityContextHolderAwareRequestWrapper(HttpServletRequest request, String rolePrefix) {
            super(request, rolePrefix);
        }

        public AsyncContext startAsync() {
            AsyncContext startAsync = super.startAsync();
            return new SecurityContextAsyncContext(startAsync);
        }

        public AsyncContext startAsync(ServletRequest servletRequest, ServletResponse servletResponse)
                throws IllegalStateException {
            AsyncContext startAsync = super.startAsync(servletRequest, servletResponse);
            return new SecurityContextAsyncContext(startAsync);
        }
    }

    private static class SecurityContextAsyncContext implements AsyncContext {
        private final AsyncContext asyncContext;

        public SecurityContextAsyncContext(AsyncContext asyncContext) {
            this.asyncContext = asyncContext;
        }

        public ServletRequest getRequest() {
            return asyncContext.getRequest();
        }

        public ServletResponse getResponse() {
            return asyncContext.getResponse();
        }

        public boolean hasOriginalRequestAndResponse() {
            return asyncContext.hasOriginalRequestAndResponse();
        }

        public void dispatch() {
            asyncContext.dispatch();
        }

        public void dispatch(String path) {
            asyncContext.dispatch(path);
        }

        public void dispatch(ServletContext context, String path) {
            asyncContext.dispatch(context, path);
        }

        public void complete() {
            asyncContext.complete();
        }

        public void start(Runnable run) {
            asyncContext.start(new DelegatingSecurityContextRunnable(run));
        }

        public void addListener(AsyncListener listener) {
            asyncContext.addListener(listener);
        }

        public void addListener(AsyncListener listener, ServletRequest request, ServletResponse response) {
            asyncContext.addListener(listener, request, response);
        }

        public <T extends AsyncListener> T createListener(Class<T> clazz) throws ServletException {
            return asyncContext.createListener(clazz);
        }

        public long getTimeout() {
            return asyncContext.getTimeout();
        }

        public void setTimeout(long timeout) {
            asyncContext.setTimeout(timeout);
        }
    }
}
