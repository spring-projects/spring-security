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

import org.springframework.security.ConfigAttributeDefinition;
import org.springframework.security.util.UrlMatcher;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.util.Map;
import java.util.LinkedHashMap;
import java.util.Iterator;
import java.util.HashMap;
import java.util.Set;
import java.util.HashSet;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;


/**
 * Default implementation of <tt>FilterInvocationDefinitionSource</tt>.
 * <p>
 * Stores an ordered map of compiled URL paths to <tt>ConfigAttributeDefinition</tt>s and provides URL matching
 * against the items stored in this map using the configured <tt>UrlMatcher</tt>.
 * <p>
 * The order of registering the regular expressions using the
 * {@link #addSecureUrl(String, ConfigAttributeDefinition)} is very important.
 * The system will identify the <b>first</b>  matching regular
 * expression for a given HTTP URL. It will not proceed to evaluate later regular expressions if a match has already
 * been found. Accordingly, the most specific regular expressions should be registered first, with the most general
 * regular expressions registered last.
 * <p>
 * If URLs are registered for a particular HTTP method using
 * {@link #addSecureUrl(String, String, ConfigAttributeDefinition)}, then the method-specific matches will take
 * precedence over any URLs which are registered without an HTTP method. 
 *
 * @author Ben Alex
 * @author Luke Taylor
 * @version $Id$
 */
public class DefaultFilterInvocationDefinitionSource implements FilterInvocationDefinitionSource {

    private static final Set HTTP_METHODS = new HashSet(Arrays.asList(new String[]{ "GET", "PUT", "DELETE", "POST" }));

    protected final Log logger = LogFactory.getLog(getClass());

    /**
     * Non method-specific map of URL patterns to <tt>ConfigAttributeDefinition</tt>s
     * TODO: Store in the httpMethod map with null key.
     */
    private Map requestMap = new LinkedHashMap();
    /** Stores request maps keyed by specific HTTP methods */
    private Map httpMethodMap = new HashMap();

    private UrlMatcher urlMatcher;

    private boolean stripQueryStringFromUrls;

    /**
     * Creates a FilterInvocationDefinitionSource with the supplied URL matching strategy.
     * @param urlMatcher
     */
    DefaultFilterInvocationDefinitionSource(UrlMatcher urlMatcher) {
        this.urlMatcher = urlMatcher;
    }

    /**
     * Builds the internal request map from the supplied map. The key elements should be of type {@link RequestKey},
     * which contains a URL path and an optional HTTP method (may be null). The path stored in the key will depend on 
     * the type of the supplied UrlMatcher.
     * 
     * @param urlMatcher typically an ant or regular expression matcher.
     * @param requestMap order-preserving map of <RequestKey, ConfigAttributeDefinition>.
     */
    public DefaultFilterInvocationDefinitionSource(UrlMatcher urlMatcher, LinkedHashMap requestMap) {
        this.urlMatcher = urlMatcher;

        Iterator iterator = requestMap.entrySet().iterator();

        while (iterator.hasNext()) {
            Map.Entry entry = (Map.Entry) iterator.next();
            RequestKey reqKey = (RequestKey) entry.getKey();
            addSecureUrl(reqKey.getUrl(), reqKey.getMethod(), (ConfigAttributeDefinition) entry.getValue());
        }
    }

    //~ Methods ========================================================================================================

    void addSecureUrl(String pattern, ConfigAttributeDefinition attr) {
        addSecureUrl(pattern, null, attr);
    }

    /**
     * Adds a URL-ConfigAttributeDefinition pair to the request map, first allowing the <tt>UrlMatcher</tt> to
     * process the pattern if required, using its <tt>compile</tt> method. The returned object will be used as the key
     * to the request map and will be passed back to the <tt>UrlMatcher</tt> when iterating through the map to find
     * a match for a particular URL.
     */
    void addSecureUrl(String pattern, String method, ConfigAttributeDefinition attr) {
        Map mapToUse = getRequestMapForHttpMethod(method);

        mapToUse.put(urlMatcher.compile(pattern), attr);

        if (logger.isDebugEnabled()) {
            logger.debug("Added URL pattern: " + pattern + "; attributes: " + attr +
                    (method == null ? "" : " for HTTP method '" + method + "'"));
        }
    }

    /**
     * Return the HTTP method specific request map, creating it if it doesn't already exist.
     * @param method GET, POST etc
     * @return map of URL patterns to <tt>ConfigAttributeDefinition</tt>s for this method.
     */
    private Map getRequestMapForHttpMethod(String method) {
        if (method == null) {
            return requestMap;
        }
        if (!HTTP_METHODS.contains(method)) {
            throw new IllegalArgumentException("Unrecognised HTTP method: '" + method + "'");
        }

        Map methodRequestmap = (Map) httpMethodMap.get(method);

        if (methodRequestmap == null) {
            methodRequestmap = new LinkedHashMap();
            httpMethodMap.put(method, methodRequestmap);
        }

        return methodRequestmap;
    }

    public Collection getConfigAttributeDefinitions() {
        return Collections.unmodifiableCollection(getRequestMap().values());
    }

    public ConfigAttributeDefinition getAttributes(Object object) throws IllegalArgumentException {
        if ((object == null) || !this.supports(object.getClass())) {
            throw new IllegalArgumentException("Object must be a FilterInvocation");
        }

        String url = ((FilterInvocation) object).getRequestUrl();
        String method = ((FilterInvocation) object).getHttpRequest().getMethod();

        return lookupAttributes(url, method);
    }

    protected ConfigAttributeDefinition lookupAttributes(String url) {
        return lookupAttributes(url, null);
    }

    /**
     * Performs the actual lookup of the relevant <code>ConfigAttributeDefinition</code> for the specified
     * <code>FilterInvocation</code>.
     * <p>
     * By default, iterates through the stored URL map and calls the
     * {@link UrlMatcher#pathMatchesUrl(Object path, String url)} method until a match is found.
     * <p>
     * Subclasses can override if required to perform any modifications to the URL.
     *
     * @param url the URI to retrieve configuration attributes for
     * @param method the HTTP method (GET, POST, DELETE...).
     *
     * @return the <code>ConfigAttributeDefinition</code> that applies to the specified <code>FilterInvocation</code>
     * or null if no match is foud
     */
    protected ConfigAttributeDefinition lookupAttributes(String url, String method) {
        if (stripQueryStringFromUrls) {
            // Strip anything after a question mark symbol, as per SEC-161. See also SEC-321
            int firstQuestionMarkIndex = url.indexOf("?");

            if (firstQuestionMarkIndex != -1) {
                url = url.substring(0, firstQuestionMarkIndex);
            }            
        }

        if (urlMatcher.requiresLowerCaseUrl()) {
            url = url.toLowerCase();

            if (logger.isDebugEnabled()) {
                logger.debug("Converted URL to lowercase, from: '" + url + "'; to: '" + url + "'");
            }
        }

        ConfigAttributeDefinition attributes = null;

        Map methodSpecificMap = (Map) httpMethodMap.get(method);

        if (methodSpecificMap != null) {
            attributes = lookupUrlInMap(methodSpecificMap, url);
        }

        if (attributes == null) {
            attributes = lookupUrlInMap(requestMap, url);
        }

        return attributes;
    }

    private ConfigAttributeDefinition lookupUrlInMap(Map requestMap, String url) {
        Iterator entries = requestMap.entrySet().iterator();

        while (entries.hasNext()) {
            Map.Entry entry = (Map.Entry) entries.next();
            Object p = entry.getKey();
            boolean matched = urlMatcher.pathMatchesUrl(p, url);

            if (logger.isDebugEnabled()) {
                logger.debug("Candidate is: '" + url + "'; pattern is " + p + "; matched=" + matched);
            }

            if (matched) {
                return (ConfigAttributeDefinition) entry.getValue();
            }
        }

        return null;
    }

    public boolean supports(Class clazz) {
        return FilterInvocation.class.isAssignableFrom(clazz);
    }

    public int getMapSize() {
        return this.requestMap.size();
    }

    Map getRequestMap() {
        return requestMap;
    }

    protected UrlMatcher getUrlMatcher() {
        return urlMatcher;
    }

    public boolean isConvertUrlToLowercaseBeforeComparison() {
        return urlMatcher.requiresLowerCaseUrl();
    }

    protected void setStripQueryStringFromUrls(boolean stripQueryStringFromUrls) {
        this.stripQueryStringFromUrls = stripQueryStringFromUrls;
    }
}
