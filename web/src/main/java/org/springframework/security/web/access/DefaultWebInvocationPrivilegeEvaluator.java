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

package org.springframework.security.web.access;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.security.Principal;
import java.util.Enumeration;
import java.util.List;
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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.intercept.AbstractSecurityInterceptor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.FilterInvocation;
import org.springframework.util.Assert;


/**
 * Allows users to determine whether they have privileges for a given web URI.
 *
 * @author Ben Alex
 * @author Luke Taylor
 * @version $Id$
 * @since 3.0
 */
public class DefaultWebInvocationPrivilegeEvaluator implements WebInvocationPrivilegeEvaluator {
    //~ Static fields/initializers =====================================================================================

    protected static final Log logger = LogFactory.getLog(DefaultWebInvocationPrivilegeEvaluator.class);

    static final FilterChain DUMMY_CHAIN = new FilterChain() {
        public void doFilter(ServletRequest req, ServletResponse res) throws IOException, ServletException {
            throw new UnsupportedOperationException("DefaultWebInvocationPrivilegeEvaluator does not support filter chains");
        }
    };

    static final HttpServletResponse DUMMY_RESPONSE = new DummyResponse();

    //~ Instance fields ================================================================================================

    private AbstractSecurityInterceptor securityInterceptor;

    //~ Constructors ===================================================================================================

    public DefaultWebInvocationPrivilegeEvaluator(AbstractSecurityInterceptor securityInterceptor) {
        Assert.notNull(securityInterceptor, "SecurityInterceptor cannot be null");
        Assert.isTrue(FilterInvocation.class.equals(securityInterceptor.getSecureObjectClass()),
            "AbstractSecurityInterceptor does not support FilterInvocations");
        Assert.notNull(securityInterceptor.getAccessDecisionManager(),
            "AbstractSecurityInterceptor must provide a non-null AccessDecisionManager");

        this.securityInterceptor = securityInterceptor;
    }

    //~ Methods ========================================================================================================

    /**
     * Determines whether the user represented by the supplied <tt>Authentication</tt> object is
     * allowed to invoke the supplied URI.
     *
     * @param uri the URI excluding the context path (a default context path setting will be used)
     */
    public boolean isAllowed(String uri, Authentication authentication) {
        return isAllowed(null, uri, null, authentication);
    }

    /**
     * Determines whether the user represented by the supplied <tt>Authentication</tt> object is
     * allowed to invoke the supplied URI, with the given .
     * <p>
     * Note the default implementation of <tt>FilterInvocationSecurityMetadataSource</tt> disregards the
     * <code>contextPath</code> when evaluating which secure object metadata applies to a given
     * request URI, so generally the <code>contextPath</code> is unimportant unless you
     * are using a custom <code>FilterInvocationSecurityMetadataSource</code>.
     *
     * @param uri the URI excluding the context path
     * @param contextPath the context path (may be null, in which case a default value will be used).
     * @param method the HTTP method (or null, for any method)
     * @param authentication the <tt>Authentication</tt> instance whose authorities should be used in evaluation
     *          whether access should be granted.
     * @return true if access is allowed, false if denied
     */
    public boolean isAllowed(String contextPath, String uri, String method, Authentication authentication) {
        Assert.notNull(uri, "uri parameter is required");

        if (contextPath == null) {
            contextPath = "/ctxpath";
        }

        FilterInvocation fi = createFilterInvocation(contextPath, uri, method);
        List<ConfigAttribute> attrs = securityInterceptor.obtainSecurityMetadataSource().getAttributes(fi);

        if (attrs == null) {
            if (securityInterceptor.isRejectPublicInvocations()) {
                return false;
            }

            return true;
        }

        if ((authentication == null) || (authentication.getAuthorities() == null)
                || authentication.getAuthorities().isEmpty()) {
            return false;
        }

        try {
            securityInterceptor.getAccessDecisionManager().decide(authentication, fi, attrs);
        } catch (AccessDeniedException unauthorized) {
            if (logger.isDebugEnabled()) {
                logger.debug(fi.toString() + " denied for " + authentication.toString(), unauthorized);
            }

            return false;
        }

        return true;
    }

    private FilterInvocation createFilterInvocation(String contextPath, String uri, String method) {
        Assert.hasText(contextPath, "contextPath required");
        Assert.hasText(uri, "URI required");

        DummyRequest req = new DummyRequest();
        req.setRequestURI(contextPath + uri);
        req.setContextPath(contextPath);
        req.setServletPath(null);
        req.setMethod(method);

        return new FilterInvocation(req, DUMMY_RESPONSE, DUMMY_CHAIN);
    }
}

@SuppressWarnings("unchecked")
class DummyRequest implements HttpServletRequest {
    private String requestURI;
    private String contextPath = "";
    private String servletPath;
    private String method;

    public void setRequestURI(String requestURI) {
        this.requestURI = requestURI;
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
        return null;
    }

    public String getQueryString() {
        return null;
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

