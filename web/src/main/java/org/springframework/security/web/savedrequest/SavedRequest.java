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

package org.springframework.security.web.savedrequest;

import org.springframework.security.web.PortResolver;
import org.springframework.security.web.util.UrlUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.util.Assert;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;


/**
 * Represents central information from a <code>HttpServletRequest</code>.<p>This class is used by {@link
 * org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter} and {@link org.springframework.security.web.wrapper.SavedRequestAwareWrapper} to
 * reproduce the request after successful authentication. An instance of this class is stored at the time of an
 * authentication exception by {@link org.springframework.security.web.access.ExceptionTranslationFilter}.</p>
 * <p><em>IMPLEMENTATION NOTE</em>: It is assumed that this object is accessed only from the context of a single
 * thread, so no synchronization around internal collection classes is performed.</p>
 * <p>This class is based on code in Apache Tomcat.</p>
 *
 * @author Craig McClanahan
 * @author Andrey Grebnev
 * @author Ben Alex
 * @version $Id$
 */
public class SavedRequest implements java.io.Serializable {
    //~ Static fields/initializers =====================================================================================

    protected static final Log logger = LogFactory.getLog(SavedRequest.class);

    public static final String SPRING_SECURITY_SAVED_REQUEST_KEY = "SPRING_SECURITY_SAVED_REQUEST_KEY";

    //~ Instance fields ================================================================================================

    private ArrayList<SavedCookie> cookies = new ArrayList<SavedCookie>();
    private ArrayList<Locale> locales = new ArrayList<Locale>();
    private Map<String, List<String>> headers = new TreeMap<String, List<String>>(String.CASE_INSENSITIVE_ORDER);
    private Map<String, String[]> parameters = new TreeMap<String, String[]>(String.CASE_INSENSITIVE_ORDER);
    private String contextPath;
    private String method;
    private String pathInfo;
    private String queryString;
    private String requestURI;
    private String requestURL;
    private String scheme;
    private String serverName;
    private String servletPath;
    private int serverPort;

    //~ Constructors ===================================================================================================

    @SuppressWarnings("unchecked")
    public SavedRequest(HttpServletRequest request, PortResolver portResolver) {
        Assert.notNull(request, "Request required");
        Assert.notNull(portResolver, "PortResolver required");

        // Cookies
        Cookie[] cookies = request.getCookies();

        if (cookies != null) {
            for (int i = 0; i < cookies.length; i++) {
                this.addCookie(cookies[i]);
            }
        }

        // Headers
        Enumeration<String> names = request.getHeaderNames();

        while (names.hasMoreElements()) {
            String name = names.nextElement();
            Enumeration<String> values = request.getHeaders(name);

            while (values.hasMoreElements()) {
                this.addHeader(name, values.nextElement());
            }
        }

        // Locales
        Enumeration<Locale> locales = request.getLocales();

        while (locales.hasMoreElements()) {
            Locale locale = (Locale) locales.nextElement();
            this.addLocale(locale);
        }

        // Parameters
        Map<String,Object> parameters = request.getParameterMap();

        for(String paramName : parameters.keySet()) {
            Object paramValues = parameters.get(paramName);
            if (paramValues instanceof String[]) {
                this.addParameter(paramName, (String[]) paramValues);
            } else {
                if (logger.isWarnEnabled()) {
                    logger.warn("ServletRequest.getParameterMap() returned non-String array");
                }
            }
        }

        // Primitives
        this.method = request.getMethod();
        this.pathInfo = request.getPathInfo();
        this.queryString = request.getQueryString();
        this.requestURI = request.getRequestURI();
        this.serverPort = portResolver.getServerPort(request);
        this.requestURL = request.getRequestURL().toString();
        this.scheme = request.getScheme();
        this.serverName = request.getServerName();
        this.contextPath = request.getContextPath();
        this.servletPath = request.getServletPath();
    }

    //~ Methods ========================================================================================================

    private void addCookie(Cookie cookie) {
        cookies.add(new SavedCookie(cookie));
    }

    private void addHeader(String name, String value) {
        List<String> values = headers.get(name);

        if (values == null) {
            values = new ArrayList<String>();
            headers.put(name, values);
        }

        values.add(value);
    }

    private void addLocale(Locale locale) {
        locales.add(locale);
    }

    private void addParameter(String name, String[] values) {
        parameters.put(name, values);
    }

    /**
     * Determines if the current request matches the <code>SavedRequest</code>. All URL arguments are
     * considered, but <em>not</em> method (POST/GET), cookies, locales, headers or parameters.
     */
    public boolean doesRequestMatch(HttpServletRequest request, PortResolver portResolver) {
        Assert.notNull(request, "Request required");
        Assert.notNull(portResolver, "PortResolver required");

        if (!propertyEquals("pathInfo", this.pathInfo, request.getPathInfo())) {
            return false;
        }

        if (!propertyEquals("queryString", this.queryString, request.getQueryString())) {
            return false;
        }

        if (!propertyEquals("requestURI", this.requestURI, request.getRequestURI())) {
            return false;
        }

        if (!propertyEquals("serverPort", new Integer(this.serverPort), new Integer(portResolver.getServerPort(request))))
        {
            return false;
        }

        if (!propertyEquals("requestURL", this.requestURL, request.getRequestURL().toString())) {
            return false;
        }

        if (!propertyEquals("scheme", this.scheme, request.getScheme())) {
            return false;
        }

        if (!propertyEquals("serverName", this.serverName, request.getServerName())) {
            return false;
        }

        if (!propertyEquals("contextPath", this.contextPath, request.getContextPath())) {
            return false;
        }

        if (!propertyEquals("servletPath", this.servletPath, request.getServletPath())) {
            return false;
        }

        return true;
    }

    public String getContextPath() {
        return contextPath;
    }

    public List<Cookie> getCookies() {
        List<Cookie> cookieList = new ArrayList<Cookie>(cookies.size());

        for (SavedCookie savedCookie : cookies) {
            cookieList.add(savedCookie.getCookie());
        }

        return cookieList;
    }

    /**
     * Indicates the URL that the user agent used for this request.
     *
     * @return the full URL of this request
     */
    public String getFullRequestUrl() {
        return UrlUtils.buildFullRequestUrl(this.getScheme(), this.getServerName(), this.getServerPort(), this.getContextPath(),
        this.getServletPath(), this.getRequestURI(), this.getPathInfo(), this.getQueryString());
    }

    public Iterator<String> getHeaderNames() {
        return (headers.keySet().iterator());
    }

    public Iterator<String> getHeaderValues(String name) {
        List<String> values = headers.get(name);

        if (values == null) {
            values = Collections.emptyList();
        }

        return (values.iterator());
    }

    public Iterator<Locale> getLocales() {
        return (locales.iterator());
    }

    public String getMethod() {
        return method;
    }

    public Map<String, String[]> getParameterMap() {
        return parameters;
    }

    public Iterator<String> getParameterNames() {
        return (parameters.keySet().iterator());
    }

    public String[] getParameterValues(String name) {
        return ((String[]) parameters.get(name));
    }

    public String getPathInfo() {
        return pathInfo;
    }

    public String getQueryString() {
        return (this.queryString);
    }

    public String getRequestURI() {
        return (this.requestURI);
    }

    public String getRequestURL() {
        return requestURL;
    }

    /**
     * Obtains the web application-specific fragment of the URL.
     *
     * @return the URL, excluding any server name, context path or servlet path
     */
    public String getRequestUrl() {
        return UrlUtils.buildRequestUrl(this.getServletPath(), this.getRequestURI(), this.getContextPath(), this.getPathInfo(),
        this.getQueryString());
    }

    public String getScheme() {
        return scheme;
    }

    public String getServerName() {
        return serverName;
    }

    public int getServerPort() {
        return serverPort;
    }

    public String getServletPath() {
        return servletPath;
    }

    private boolean propertyEquals(String log, Object arg1, Object arg2) {
        if ((arg1 == null) && (arg2 == null)) {
            if (logger.isDebugEnabled()) {
                logger.debug(log + ": both null (property equals)");
            }

            return true;
        }

        if (((arg1 == null) && (arg2 != null)) || ((arg1 != null) && (arg2 == null))) {
            if (logger.isDebugEnabled()) {
                logger.debug(log + ": arg1=" + arg1 + "; arg2=" + arg2 + " (property not equals)");
            }

            return false;
        }

        if (arg1.equals(arg2)) {
            if (logger.isDebugEnabled()) {
                logger.debug(log + ": arg1=" + arg1 + "; arg2=" + arg2 + " (property equals)");
            }

            return true;
        } else {
            if (logger.isDebugEnabled()) {
                logger.debug(log + ": arg1=" + arg1 + "; arg2=" + arg2 + " (property not equals)");
            }

            return false;
        }
    }

    public String toString() {
        return "SavedRequest[" + getFullRequestUrl() + "]";
    }
}
