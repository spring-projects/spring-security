/* Copyright 2004 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.sf.acegisecurity.intercept.web;

import javax.servlet.FilterChain;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


/**
 * Holds objects associated with a HTTP filter.
 * 
 * <P>
 * Guarantees the request and response are instances of
 * <code>HttpServletRequest</code> and <code>HttpServletResponse</code>, and
 * that there are no <code>null</code> objects.
 * </p>
 * 
 * <P>
 * Required so that security system classes can obtain access to the filter
 * environment, as well as the request and response.
 * </p>
 *
 * @author Ben Alex
 * @author colin sampaleanu
 * @version $Id$
 */
public class FilterInvocation {
    //~ Instance fields ========================================================

    private FilterChain chain;
    private ServletRequest request;
    private ServletResponse response;

    //~ Constructors ===========================================================

    public FilterInvocation(ServletRequest request, ServletResponse response,
        FilterChain chain) {
        if ((request == null) || (response == null) || (chain == null)) {
            throw new IllegalArgumentException(
                "Cannot pass null values to constructor");
        }

        if (!(request instanceof HttpServletRequest)) {
            throw new IllegalArgumentException(
                "Can only process HttpServletRequest");
        }

        if (!(response instanceof HttpServletResponse)) {
            throw new IllegalArgumentException(
                "Can only process HttpServletResponse");
        }

        this.request = request;
        this.response = response;
        this.chain = chain;
    }

    protected FilterInvocation() {
        throw new IllegalArgumentException("Cannot use default constructor");
    }

    //~ Methods ================================================================

    public FilterChain getChain() {
        return chain;
    }

    public String getFullRequestUrl() {
        return getHttpRequest().getRequestURL().toString()
        + ((getHttpRequest().getQueryString() == null) ? ""
                                                       : ("?"
        + getHttpRequest().getQueryString()));
    }

    public HttpServletRequest getHttpRequest() {
        return (HttpServletRequest) request;
    }

    public HttpServletResponse getHttpResponse() {
        return (HttpServletResponse) response;
    }

    public ServletRequest getRequest() {
        return request;
    }

    public String getRequestUrl() {
        String pathInfo = getHttpRequest().getPathInfo();
        String queryString = getHttpRequest().getQueryString();
        
        return getHttpRequest().getServletPath() + (pathInfo == null ? "" : pathInfo)
                + (queryString == null ? "" : ("?" + queryString));
    }

    public ServletResponse getResponse() {
        return response;
    }

    public String toString() {
        return "FilterInvocation: URL: " + getRequestUrl();
    }
}
