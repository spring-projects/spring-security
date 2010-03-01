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

package org.springframework.security.web;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.security.Principal;
import java.util.Enumeration;
import java.util.Locale;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.ServletOutputStream;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.security.web.util.UrlUtils;


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
 */
public class FilterInvocation {
    //~ Static fields ==================================================================================================
    static final FilterChain DUMMY_CHAIN = new FilterChain() {
        public void doFilter(ServletRequest req, ServletResponse res) throws IOException, ServletException {
            throw new UnsupportedOperationException("Dummy filter chain");
        }
    };

    static final HttpServletResponse DUMMY_RESPONSE = new DummyResponse();

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

    public FilterInvocation(String servletPath, String method) {
        this(null, servletPath, method);
    }

    public FilterInvocation(String contextPath, String servletPath, String method) {
        this(contextPath, servletPath, null, null, method);
    }

    public FilterInvocation(String contextPath, String servletPath, String pathInfo, String query, String method) {
        DummyRequest request = new DummyRequest();
        if (contextPath == null) {
            contextPath = "/cp";
        }
        request.setContextPath(contextPath);
        request.setServletPath(servletPath);
        request.setPathInfo(pathInfo);
        request.setMethod(method);
        this.request = request;
    }

    //~ Methods ========================================================================================================

    public FilterChain getChain() {
        return chain;
    }

    /**
     * Indicates the URL that the user agent used for this request.
     * <p>
     * The returned URL does <b>not</b> reflect the port number determined from a
     * {@link org.springframework.security.web.PortResolver}.
     *
     * @return the full URL of this request
     */
    public String getFullRequestUrl() {
        return UrlUtils.buildFullRequestUrl(request);
    }

    public HttpServletRequest getHttpRequest() {
        return request;
    }

    public HttpServletResponse getHttpResponse() {
        return response;
    }

    /**
     * Obtains the web application-specific fragment of the URL.
     *
     * @return the URL, excluding any server name, context path or servlet path
     */
    public String getRequestUrl() {
        return UrlUtils.buildRequestUrl(request);
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

@SuppressWarnings("unchecked")
class DummyRequest implements HttpServletRequest {
    private String requestURI;
    private String contextPath = "";
    private String servletPath;
    private String pathInfo;
    private String queryString;
    private String method;

    public void setRequestURI(String requestURI) {
        this.requestURI = requestURI;
    }

    public void setPathInfo(String pathInfo) {
        this.pathInfo = pathInfo;
    }

    public String getRequestURI() {
        return requestURI;
    }

    public void setContextPath(String contextPath) {
        this.contextPath = contextPath;
    }

    public String getContextPath() {
        return contextPath;
    }

    public void setServletPath(String servletPath) {
        this.servletPath = servletPath;
    }

    public String getServletPath() {
        return servletPath;
    }

    public void setMethod(String method) {
        this.method = method;
    }

    public String getMethod() {
        return method;
    }

    public String getPathInfo() {
        return pathInfo;
    }

    public String getQueryString() {
        return queryString;
    }

    public void setQueryString(String queryString) {
        this.queryString = queryString;
    }


    public String getAuthType() {
        throw new UnsupportedOperationException();
    }

    public Cookie[] getCookies() {
        throw new UnsupportedOperationException();
    }

    public long getDateHeader(String name) {
        throw new UnsupportedOperationException();
    }

    public String getHeader(String name) {
        throw new UnsupportedOperationException();
    }

    public Enumeration getHeaderNames() {
        throw new UnsupportedOperationException();
    }

    public Enumeration getHeaders(String name) {
        throw new UnsupportedOperationException();
    }

    public int getIntHeader(String name) {
        throw new UnsupportedOperationException();
    }

    public String getPathTranslated() {
        throw new UnsupportedOperationException();
    }

    public String getRemoteUser() {
        throw new UnsupportedOperationException();
    }

    public StringBuffer getRequestURL() {
        throw new UnsupportedOperationException();
    }

    public String getRequestedSessionId() {
        throw new UnsupportedOperationException();
    }

    public HttpSession getSession() {
        throw new UnsupportedOperationException();
    }

    public HttpSession getSession(boolean create) {
        throw new UnsupportedOperationException();
    }

    public Principal getUserPrincipal() {
        throw new UnsupportedOperationException();
    }

    public boolean isRequestedSessionIdFromCookie() {
        throw new UnsupportedOperationException();
    }

    public boolean isRequestedSessionIdFromURL() {
        throw new UnsupportedOperationException();
    }

    public boolean isRequestedSessionIdFromUrl() {
        throw new UnsupportedOperationException();
    }

    public boolean isRequestedSessionIdValid() {
        throw new UnsupportedOperationException();
    }

    public boolean isUserInRole(String role) {
        throw new UnsupportedOperationException();
    }

    public Object getAttribute(String name) {
        throw new UnsupportedOperationException();
    }

    public Enumeration getAttributeNames() {
        throw new UnsupportedOperationException();
    }

    public String getCharacterEncoding() {
        throw new UnsupportedOperationException();
    }

    public int getContentLength() {
        throw new UnsupportedOperationException();
    }

    public String getContentType() {
        throw new UnsupportedOperationException();
    }

    public ServletInputStream getInputStream() throws IOException {
        throw new UnsupportedOperationException();
    }

    public String getLocalAddr() {
        throw new UnsupportedOperationException();

    }

    public String getLocalName() {
        throw new UnsupportedOperationException();
    }

    public int getLocalPort() {
        throw new UnsupportedOperationException();
    }

    public Locale getLocale() {
        throw new UnsupportedOperationException();
    }

    public Enumeration getLocales() {
        throw new UnsupportedOperationException();
    }

    public String getParameter(String name) {
        throw new UnsupportedOperationException();
    }

    public Map getParameterMap() {
        throw new UnsupportedOperationException();
    }

    public Enumeration getParameterNames() {
        throw new UnsupportedOperationException();
    }

    public String[] getParameterValues(String name) {
        throw new UnsupportedOperationException();
    }

    public String getProtocol() {
        throw new UnsupportedOperationException();
    }

    public BufferedReader getReader() throws IOException {
        throw new UnsupportedOperationException();
    }

    public String getRealPath(String path) {
        throw new UnsupportedOperationException();
    }

    public String getRemoteAddr() {
        throw new UnsupportedOperationException();
    }

    public String getRemoteHost() {
        throw new UnsupportedOperationException();
    }

    public int getRemotePort() {
        throw new UnsupportedOperationException();
    }

    public RequestDispatcher getRequestDispatcher(String path) {
        throw new UnsupportedOperationException();
    }

    public String getScheme() {
        throw new UnsupportedOperationException();
    }

    public String getServerName() {
        throw new UnsupportedOperationException();
    }

    public int getServerPort() {
        throw new UnsupportedOperationException();
    }

    public boolean isSecure() {
        throw new UnsupportedOperationException();
    }

    public void removeAttribute(String name) {
        throw new UnsupportedOperationException();
    }

    public void setAttribute(String name, Object o) {
        throw new UnsupportedOperationException();
    }

    public void setCharacterEncoding(String env) throws UnsupportedEncodingException {
        throw new UnsupportedOperationException();
    }
}

class DummyResponse implements HttpServletResponse {
    public void addCookie(Cookie cookie) {
        throw new UnsupportedOperationException();
    }

    public void addDateHeader(String name, long date) {
        throw new UnsupportedOperationException();
    }

    public void addHeader(String name, String value) {
        throw new UnsupportedOperationException();
    }

    public void addIntHeader(String name, int value) {
        throw new UnsupportedOperationException();
    }

    public boolean containsHeader(String name) {
        throw new UnsupportedOperationException();
    }

    public String encodeRedirectURL(String url) {
        throw new UnsupportedOperationException();
    }

    public String encodeRedirectUrl(String url) {
        throw new UnsupportedOperationException();
    }

    public String encodeURL(String url) {
        throw new UnsupportedOperationException();
    }

    public String encodeUrl(String url) {
        throw new UnsupportedOperationException();
    }

    public void sendError(int sc) throws IOException {
        throw new UnsupportedOperationException();

    }

    public void sendError(int sc, String msg) throws IOException {
        throw new UnsupportedOperationException();
    }

    public void sendRedirect(String location) throws IOException {
        throw new UnsupportedOperationException();
    }

    public void setDateHeader(String name, long date) {
        throw new UnsupportedOperationException();
    }

    public void setHeader(String name, String value) {
        throw new UnsupportedOperationException();
    }

    public void setIntHeader(String name, int value) {
        throw new UnsupportedOperationException();
    }

    public void setStatus(int sc) {
        throw new UnsupportedOperationException();
    }

    public void setStatus(int sc, String sm) {
        throw new UnsupportedOperationException();
    }

    public void flushBuffer() throws IOException {
        throw new UnsupportedOperationException();
    }

    public int getBufferSize() {
        throw new UnsupportedOperationException();
    }

    public String getCharacterEncoding() {
        throw new UnsupportedOperationException();
    }

    public String getContentType() {
        throw new UnsupportedOperationException();
    }

    public Locale getLocale() {
        throw new UnsupportedOperationException();
    }

    public ServletOutputStream getOutputStream() throws IOException {
        throw new UnsupportedOperationException();
    }

    public PrintWriter getWriter() throws IOException {
        throw new UnsupportedOperationException();
    }

    public boolean isCommitted() {
        throw new UnsupportedOperationException();
    }

    public void reset() {
        throw new UnsupportedOperationException();
    }

    public void resetBuffer() {
        throw new UnsupportedOperationException();
    }

    public void setBufferSize(int size) {
        throw new UnsupportedOperationException();
    }

    public void setCharacterEncoding(String charset) {
        throw new UnsupportedOperationException();
    }

    public void setContentLength(int len) {
        throw new UnsupportedOperationException();
    }

    public void setContentType(String type) {
        throw new UnsupportedOperationException();
    }

    public void setLocale(Locale loc) {
        throw new UnsupportedOperationException();
    }
}
