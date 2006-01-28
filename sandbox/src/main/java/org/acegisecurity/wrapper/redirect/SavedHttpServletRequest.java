/* Copyright 2004, 2005 Acegi Technology Pty Limited
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

package org.acegisecurity.wrapper.redirect;

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import org.acegisecurity.ui.ExceptionTranslationFilter;
import org.acegisecurity.wrapper.SecurityContextHolderAwareRequestWrapper;

/**
 * <p>
 * Object that saves the critical information from a request so that
 * HTTP (header and parameter)-based authentication can reproduce it
 * once the user has been authenticated.
 * <p>
 * <b>IMPLEMENTATION NOTE</b> - It is assumed that this object is accessed
 * only from the context of a single thread, so no synchronization around
 * internal collection classes is performed.
 * <p>
 * Note that SavedHttpServletRequest doesn't save uploaded file binary data, although
 * it does save request parameters so that a POST transaction can be faithfully
 * duplicated.  On one hand it is unfortunate to lose such type of data, but on
 * the other hand we don't store it in session because the data can be very big
 * and this solution can overload restricted resources.
 * </p>
 * <p>The original source code from Apache Tomcat<p>
 *
 * @see ExceptionTranslationFilter
 * @see SecurityContextHolderAwareRequestWrapper
 * @author Craig R. McClanahan
 * @author Andrey Grebnev <a href="mailto:andrey.grebnev@blandware.com">&lt;andrey.grebnev@blandware.com&gt;</a>
 * @version $Revision$ $Date$
 */
public class SavedHttpServletRequest {

    /**
     * This method provides ability to create SavedHttpServletRequest from HttpServletRequest
     * @param request           request to be saved
     * @return saved request    resulting SavedHttpServletRequest
     */
    public static SavedHttpServletRequest saveRequest(HttpServletRequest request) {
        if (request.getRequestURI() == null)
            return null;

        // Create and populate a SavedHttpServletRequest object for this request
        SavedHttpServletRequest saved = new SavedHttpServletRequest();
        Cookie cookies[] = request.getCookies();
        if (cookies != null) {
            for (int i = 0; i < cookies.length; i++)
                saved.addCookie(cookies[i]);
        }
        Enumeration names = request.getHeaderNames();
        while (names.hasMoreElements()) {
            String name = (String) names.nextElement();
            Enumeration values = request.getHeaders(name);
            while (values.hasMoreElements()) {
                String value = (String) values.nextElement();
                saved.addHeader(name, value);
            }
        }
        Enumeration locales = request.getLocales();
        while (locales.hasMoreElements()) {
            Locale locale = (Locale) locales.nextElement();
            saved.addLocale(locale);
        }
        Map parameters = request.getParameterMap();
        Iterator paramNames = parameters.keySet().iterator();
        while (paramNames.hasNext()) {
            String paramName = (String) paramNames.next();
            String paramValues[] = (String[]) parameters.get(paramName);
            saved.addParameter(paramName, paramValues);
        }
        saved.setMethod(request.getMethod());
        saved.setQueryString(request.getQueryString());
        saved.setRequestURI(request.getRequestURI());
//        saved.setPathInfo(request.getPathInfo());

        return saved;
    }

    /**
     * The set of Cookies associated with this Request.
     */
    private ArrayList cookies = new ArrayList();

    /**
     * The set of Headers associated with this Request.  Each key is a header
     * name, while the value is a ArrayList containing one or more actual
     * values for this header.  The values are returned as an Iterator when
     * you ask for them.
     */
    private HashMap headers = new HashMap();

    /**
     * The set of Locales associated with this Request.
     */
    private ArrayList locales = new ArrayList();

    /**
     * The request method used on this Request.
     */
    private String method = null;

    /**
     * The set of request parameters associated with this Request.  Each
     * entry is keyed by the parameter name, pointing at a String array of
     * the corresponding values.
     */
    private HashMap parameters = new HashMap();

    /**
     * The request pathInfo associated with this Request.
     */
    private String pathInfo = null;

    /**
     * The query string associated with this Request.
     */
    private String queryString = null;

    /**
     * The request URI associated with this Request.
     */
    private String requestURI = null;

    /**
     * Adds cookie to list of cookies
     *
     * @param cookie cookie to add
     */
    public void addCookie(Cookie cookie) {
        cookies.add(cookie);
    }

    /**
     * Adds header
     *
     * @param name  header name
     * @param value header value
     */
    public void addHeader(String name, String value) {
        ArrayList values = (ArrayList) headers.get(name);
        if (values == null) {
            values = new ArrayList();
            headers.put(name, values);
        }
        values.add(value);
    }

    /**
     * Adds locale
     *
     * @param locale locale to add
     */
    public void addLocale(Locale locale) {
        locales.add(locale);
    }

    /**
     * Adds parameter
     *
     * @param name      parameter name
     * @param values    parameter values
     */
    public void addParameter(String name, String values[]) {
        parameters.put(name, values);
    }

    /**
     * Returns list of cookies
     *
     * @return list of cookies
     */
    public List getCookies() {
        return cookies;
    }

    /**
     * Returns iterator over header names
     *
     * @return iterator over header names
     */
    public Iterator getHeaderNames() {
        return (headers.keySet().iterator());
    }

    /**
     * Returns iterator over header values
     *
     * @param name header name
     * @return iterator over header values
     */
    public Iterator getHeaderValues(String name) {
        ArrayList values = (ArrayList) headers.get(name);
        if (values == null)
            return ((new ArrayList()).iterator());
        else
            return (values.iterator());
    }

    /**
     * Returns iterator over locales
     *
     * @return iterator over locales
     */
    public Iterator getLocales() {
        return (locales.iterator());
    }

    /**
     * Returns request method
     *
     * @return request method
     */
    public String getMethod() {
        return (this.method);
    }

    /**
     * Returns parameters
     *
     * @return parameters map
     */
    public Map getParameterMap() {
        return parameters;
    }

    /**
     * Returns iterator over parameter names
     *
     * @return iterator over parameter names
     */
    public Iterator getParameterNames() {
        return (parameters.keySet().iterator());
    }

    /**
     * Returns parameter values
     *
     * @param name parameter name
     * @return parameter values
     */
    public String[] getParameterValues(String name) {
        return ((String[]) parameters.get(name));
    }

    /**
     * Returns path info
     *
     * @return path info
     */
    public String getPathInfo() {
        return pathInfo;
    }

    /**
     * Returns query string
     *
     * @return query string
     */
    public String getQueryString() {
        return (this.queryString);
    }

    /**
     * Returns request URI
     *
     * @return request URI
     */
    public String getRequestURI() {
        return (this.requestURI);
    }

    /**
     * Gets uri with path info and query string
     *
     * @return uri with path info and query string
     */
    public String getRequestURL() {
        if (getRequestURI() == null)
            return null;

        StringBuffer sb = new StringBuffer(getRequestURI());
//        if (getPathInfo() != null) {
//            sb.append(getPathInfo());
//        }
        if (getQueryString() != null) {
            sb.append('?');
            sb.append(getQueryString());
        }
        return sb.toString();
    }

    /**
     * Sets request method
     *
     * @param method request method to set
     */
    public void setMethod(String method) {
        this.method = method;
    }

    /**
     * Sets path info
     *
     * @param pathInfo path info to set
     */
    public void setPathInfo(String pathInfo) {
        this.pathInfo = pathInfo;
    }

    /**
     * Sets query string
     *
     * @param queryString query string to set
     */
    public void setQueryString(String queryString) {
        this.queryString = queryString;
    }

    /**
     * Sets request URI
     *
     * @param requestURI request URI to set
     */
    public void setRequestURI(String requestURI) {
        this.requestURI = requestURI;
    }

}
