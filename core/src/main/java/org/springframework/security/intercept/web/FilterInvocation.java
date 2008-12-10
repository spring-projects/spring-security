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

package org.springframework.security.intercept.web;

import org.springframework.security.util.UrlUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


/**
 * Holds objects associated with a HTTP filter.<P>Guarantees the request and response are instances of
 * <code>HttpServletRequest</code> and <code>HttpServletResponse</code>, and that there are no <code>null</code>
 * objects.
 * <p>
 * Required so that security system classes can obtain access to the filter environment, as well as the request
 * and response.
 *
 * @author Ben Alex
 * @author colin sampaleanu
 * @version $Id$
 */
public class FilterInvocation {
    //~ Instance fields ================================================================================================

    private FilterChain chain;
    private HttpServletRequest request;
    private HttpServletResponse response;

    //~ Constructors ===================================================================================================

    public FilterInvocation(ServletRequest request, ServletResponse response, FilterChain chain) {
        if ((request == null) || (response == null) || (chain == null)) {
            throw new IllegalArgumentException("Cannot pass null values to constructor");
        }

        this.request = (HttpServletRequest) request;
        this.response = (HttpServletResponse) response;
        this.chain = chain;
    }

    //~ Methods ========================================================================================================

    public FilterChain getChain() {
        return chain;
    }

    /**
     * Indicates the URL that the user agent used for this request.
     * <p>
     * The returned URL does <b>not</b> reflect the port number determined from a
     * {@link org.springframework.security.util.PortResolver}.
     *
     * @return the full URL of this request
     */
    public String getFullRequestUrl() {
        return UrlUtils.getFullRequestUrl(this);
    }

    public HttpServletRequest getHttpRequest() {
        return request;
    }

    public HttpServletResponse getHttpResponse() {
        return (HttpServletResponse) response;
    }

    /**
     * Obtains the web application-specific fragment of the URL.
     *
     * @return the URL, excluding any server name, context path or servlet path
     */
    public String getRequestUrl() {
        return UrlUtils.getRequestUrl(this);
    }

    public HttpServletRequest getRequest() {
        return getHttpRequest();
    }

    public HttpServletResponse getResponse() {
        return getHttpResponse();
    }

    public String toString() {
        return "FilterInvocation: URL: " + getRequestUrl();
    }
}
