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

package net.sf.acegisecurity;

import java.io.BufferedReader;
import java.io.IOException;

import java.security.Principal;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletInputStream;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;


/**
 * Mocks a <code>HttpServletRequest</code> and provides the
 * <code>getUserPrincipal()</code>, <code>getContextPath()</code>,
 * <code>getServletPath()</code> and <code>getSession()</code> methods.
 * 
 * <P>
 * Also provides a convenience <code>Map</code> for storing request parameters.
 * </p>
 *
 * @author Ben Alex
 * @author colin sampaleanu
 * @version $Id$
 */
public class MockHttpServletRequest implements HttpServletRequest {
    //~ Instance fields ========================================================

    private HttpSession session = new MockHttpSession();
    private Map headersMap = new HashMap();
    private Map paramMap = new HashMap();
    private Principal principal;
    private String contextPath = "";
    private String pathInfo; // null for no extra path
    private String queryString = null;
    private String requestURL;
    private String scheme;
    private String serverName;
    private String servletPath;
    private int serverPort;

    //~ Constructors ===========================================================

    public MockHttpServletRequest(Principal principal, HttpSession session) {
        this.principal = principal;
        this.session = session;
    }

    public MockHttpServletRequest(String queryString) {
        this.queryString = queryString;
    }

    public MockHttpServletRequest(Map headers, Principal principal,
        HttpSession session) {
        this.headersMap = headers;
        this.principal = principal;
        this.session = session;
    }

    private MockHttpServletRequest() {
        super();
    }

    //~ Methods ================================================================

    public void setAttribute(String arg0, Object arg1) {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public Object getAttribute(String arg0) {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public Enumeration getAttributeNames() {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public String getAuthType() {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public void setCharacterEncoding(String arg0) {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public String getCharacterEncoding() {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public int getContentLength() {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public String getContentType() {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public void setContextPath(String contextPath) {
        this.contextPath = contextPath;
    }

    public String getContextPath() {
        return contextPath;
    }

    public Cookie[] getCookies() {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public long getDateHeader(String arg0) {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public String getHeader(String arg0) {
        Object result = headersMap.get(arg0);

        if (result != null) {
            return (String) headersMap.get(arg0);
        } else {
            return null;
        }
    }

    public Enumeration getHeaderNames() {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public Enumeration getHeaders(String arg0) {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public ServletInputStream getInputStream() throws IOException {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public int getIntHeader(String arg0) {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public Locale getLocale() {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public Enumeration getLocales() {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public String getMethod() {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public void setParameter(String arg0, String value) {
        paramMap.put(arg0, value);
    }

    public String getParameter(String arg0) {
        Object result = paramMap.get(arg0);

        if (result != null) {
            return (String) paramMap.get(arg0);
        } else {
            return null;
        }
    }

    public Map getParameterMap() {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public Enumeration getParameterNames() {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public String[] getParameterValues(String arg0) {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public void setPathInfo(String pathInfo) {
        this.pathInfo = pathInfo;
    }

    public String getPathInfo() {
        return pathInfo;
    }

    public String getPathTranslated() {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public String getProtocol() {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public String getQueryString() {
        return this.queryString;
    }

    public BufferedReader getReader() throws IOException {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public String getRealPath(String arg0) {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public String getRemoteAddr() {
        return "127.0.0.1";
    }

    public String getRemoteHost() {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public String getRemoteUser() {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public RequestDispatcher getRequestDispatcher(String arg0) {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public String getRequestURI() {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public void setRequestURL(String requestURL) {
        this.requestURL = requestURL;
    }

    public StringBuffer getRequestURL() {
        return new StringBuffer(requestURL);
    }

    public String getRequestedSessionId() {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public boolean isRequestedSessionIdFromCookie() {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public boolean isRequestedSessionIdFromURL() {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public boolean isRequestedSessionIdFromUrl() {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public boolean isRequestedSessionIdValid() {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public void setScheme(String scheme) {
        this.scheme = scheme;
    }

    public String getScheme() {
        return scheme;
    }

    public boolean isSecure() {
        if ("https".equals(scheme)) {
            return true;
        } else {
            return false;
        }
    }

    public void setServerName(String serverName) {
        this.serverName = serverName;
    }

    public String getServerName() {
        return serverName;
    }

    public void setServerPort(int serverPort) {
        this.serverPort = serverPort;
    }

    public int getServerPort() {
        return serverPort;
    }

    public void setServletPath(String servletPath) {
        this.servletPath = servletPath;
    }

    public String getServletPath() {
        return this.servletPath;
    }

    public HttpSession getSession(boolean arg0) {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public HttpSession getSession() {
        return this.session;
    }

    public boolean isUserInRole(String arg0) {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public Principal getUserPrincipal() {
        return this.principal;
    }

    public void removeAttribute(String arg0) {
        throw new UnsupportedOperationException("mock method not implemented");
    }
}
