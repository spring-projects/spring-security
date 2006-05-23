/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.acegisecurity.intercept.web;

import org.acegisecurity.util.UrlUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


/**
 * Holds objects associated with a HTTP filter.<P>Guarantees the request and response are instances of
 * <code>HttpServletRequest</code> and <code>HttpServletResponse</code>, and that there are no <code>null</code>
 * objects.</p>
 *  <P>Required so that security system classes can obtain access to the filter environment, as well as the request
 * and response.</p>
 *
 * @author Ben Alex
 * @author colin sampaleanu
 * @version $Id$
 */
public class FilterInvocation {
    //~ Instance fields ================================================================================================

    private FilterChain chain;
    private ServletRequest request;
    private ServletResponse response;

    //~ Constructors ===================================================================================================

    public FilterInvocation(ServletRequest request, ServletResponse response, FilterChain chain) {
        if ((request == null) || (response == null) || (chain == null)) {
            throw new IllegalArgumentException("Cannot pass null values to constructor");
        }

        if (!(request instanceof HttpServletRequest)) {
            throw new IllegalArgumentException("Can only process HttpServletRequest");
        }

        if (!(response instanceof HttpServletResponse)) {
            throw new IllegalArgumentException("Can only process HttpServletResponse");
        }

        this.request = request;
        this.response = response;
        this.chain = chain;
    }

    //~ Methods ========================================================================================================

    public FilterChain getChain() {
        return chain;
    }

    /**
     * Indicates the URL that the user agent used for this request.<P>The returned URL does <b>not</b> reflect
     * the port number determined from a {@link org.acegisecurity.util.PortResolver}.</p>
     *
     * @return the full URL of this request
     */
    public String getFullRequestUrl() {
        return UrlUtils.getFullRequestUrl(this);
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

    /**
     * Obtains the web application-specific fragment of the URL.
     *
     * @return the URL, excluding any server name, context path or servlet path
     */
    public String getRequestUrl() {
        return UrlUtils.getRequestUrl(this);
    }

    public ServletResponse getResponse() {
        return response;
    }

    public String toString() {
        return "FilterInvocation: URL: " + getRequestUrl();
    }
}
