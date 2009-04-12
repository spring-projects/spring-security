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

package org.springframework.security.web.intercept;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.util.UrlMatcher;
import org.springframework.security.web.FilterInvocation;


/**
 * Default implementation of <tt>FilterInvocationDefinitionSource</tt>.
 * <p>
 * Stores an ordered map of compiled URL paths to <tt>ConfigAttribute</tt> lists and provides URL matching
 * against the items stored in this map using the configured <tt>UrlMatcher</tt>.
 * <p>
 * The order of registering the regular expressions using the
 * {@link #addSecureUrl(String, List<ConfigAttribute>)} is very important.
 * The system will identify the <b>first</b>  matching regular
 * expression for a given HTTP URL. It will not proceed to evaluate later regular expressions if a match has already
 * been found. Accordingly, the most specific regular expressions should be registered first, with the most general
 * regular expressions registered last.
 * <p>
 * If URLs are registered for a particular HTTP method using
 * {@link #addSecureUrl(String, String, List<ConfigAttribute>)}, then the method-specific matches will take
 * precedence over any URLs which are registered without an HTTP method.
 *
 * @author Ben Alex
 * @author Luke Taylor
 * @version $Id$
 */
public class DefaultFilterInvocationSecurityMetadataSource implements FilterInvocationSecurityMetadataSource {

    private static final Set<String> HTTP_METHODS = new HashSet<String>(Arrays.asList("DELETE", "GET", "HEAD", "OPTIONS", "POST", "PUT", "TRACE"));

    protected final Log logger = LogFactory.getLog(getClass());

    //private Map<Object, List<ConfigAttribute>> requestMap = new LinkedHashMap<Object, List<ConfigAttribute>>();
    /** Stores request maps keyed by specific HTTP methods. A null key matches any method */
    private Map<String, Map<Object, List<ConfigAttribute>>> httpMethodMap =
        new HashMap<String, Map<Object, List<ConfigAttribute>>>();

    private UrlMatcher urlMatcher;

    private boolean stripQueryStringFromUrls;

    //~ Constructors ===================================================================================================

    /**
     * Builds the internal request map from the supplied map. The key elements should be of type {@link RequestKey},
     * which contains a URL path and an optional HTTP method (may be null). The path stored in the key will depend on
     * the type of the supplied UrlMatcher.
     *
     * @param urlMatcher typically an ant or regular expression matcher.
     * @param requestMap order-preserving map of request definitions to attribute lists
     */
    public DefaultFilterInvocationSecurityMetadataSource(UrlMatcher urlMatcher,
            LinkedHashMap<RequestKey, List<ConfigAttribute>> requestMap) {
        this.urlMatcher = urlMatcher;

        for (Map.Entry<RequestKey, List<ConfigAttribute>> entry : requestMap.entrySet()) {
            addSecureUrl(entry.getKey().getUrl(), entry.getKey().getMethod(), entry.getValue());
        }
    }

    //~ Methods ========================================================================================================

    /**
     * Adds a URL,attribute-list pair to the request map, first allowing the <tt>UrlMatcher</tt> to
     * process the pattern if required, using its <tt>compile</tt> method. The returned object will be used as the key
     * to the request map and will be passed back to the <tt>UrlMatcher</tt> when iterating through the map to find
     * a match for a particular URL.
     */
    private void addSecureUrl(String pattern, String method, List<ConfigAttribute> attr) {
        Map<Object, List<ConfigAttribute>> mapToUse = getRequestMapForHttpMethod(method);

        mapToUse.put(urlMatcher.compile(pattern), attr);

        if (logger.isDebugEnabled()) {
            logger.debug("Added URL pattern: " + pattern + "; attributes: " + attr +
                    (method == null ? "" : " for HTTP method '" + method + "'"));
        }
    }

    /**
     * Return the HTTP method specific request map, creating it if it doesn't already exist.
     * @param method GET, POST etc
     * @return map of URL patterns to <tt>ConfigAttribute</tt>s for this method.
     */
    private Map<Object, List<ConfigAttribute>> getRequestMapForHttpMethod(String method) {
        if (method != null && !HTTP_METHODS.contains(method)) {
            throw new IllegalArgumentException("Unrecognised HTTP method: '" + method + "'");
        }

        Map<Object, List<ConfigAttribute>> methodRequestMap = httpMethodMap.get(method);

        if (methodRequestMap == null) {
            methodRequestMap = new LinkedHashMap<Object, List<ConfigAttribute>>();
            httpMethodMap.put(method, methodRequestMap);
        }

        return methodRequestMap;
    }

    public Collection<ConfigAttribute> getAllConfigAttributes() {
        Set<ConfigAttribute> allAttributes = new HashSet<ConfigAttribute>();

        for (Map.Entry<String, Map<Object, List<ConfigAttribute>>> entry : httpMethodMap.entrySet()) {
            for (List<ConfigAttribute> attrs : entry.getValue().values()) {
                allAttributes.addAll(attrs);
            }
        }

        return allAttributes;
    }


    public List<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {
        if ((object == null) || !this.supports(object.getClass())) {
            throw new IllegalArgumentException("Object must be a FilterInvocation");
        }

        String url = ((FilterInvocation) object).getRequestUrl();
        String method = ((FilterInvocation) object).getHttpRequest().getMethod();

        return lookupAttributes(url, method);
    }

    /**
     * Performs the actual lookup of the relevant <tt>ConfigAttribute</tt>s for the given <code>FilterInvocation</code>.
     * <p>
     * By default, iterates through the stored URL map and calls the
     * {@link UrlMatcher#pathMatchesUrl(Object path, String url)} method until a match is found.
     * <p>
     * Subclasses can override if required to perform any modifications to the URL.
     *
     * @param url the URI to retrieve configuration attributes for
     * @param method the HTTP method (GET, POST, DELETE...).
     *
     * @return the <code>ConfigAttribute</code>s that apply to the specified <code>FilterInvocation</code>
     * or null if no match is found
     */
    public final List<ConfigAttribute> lookupAttributes(String url, String method) {
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

        // Obtain the map of request patterns to attributes for this method and lookup the url.
        Map<Object, List<ConfigAttribute>> requestMap = httpMethodMap.get(method);

        // If no method-specific map, use the general one stored under the null key
        if (requestMap == null) {
            requestMap = httpMethodMap.get(null);
        }

        if (requestMap != null) {
            for (Map.Entry<Object, List<ConfigAttribute>> entry : requestMap.entrySet()) {
                Object p = entry.getKey();
                boolean matched = urlMatcher.pathMatchesUrl(entry.getKey(), url);

                if (logger.isDebugEnabled()) {
                    logger.debug("Candidate is: '" + url + "'; pattern is " + p + "; matched=" + matched);
                }

                if (matched) {
                    return entry.getValue();
                }
            }
        }

        return null;
    }

    public boolean supports(Class<?> clazz) {
        return FilterInvocation.class.isAssignableFrom(clazz);
    }

    protected UrlMatcher getUrlMatcher() {
        return urlMatcher;
    }

    public boolean isConvertUrlToLowercaseBeforeComparison() {
        return urlMatcher.requiresLowerCaseUrl();
    }

    public void setStripQueryStringFromUrls(boolean stripQueryStringFromUrls) {
        this.stripQueryStringFromUrls = stripQueryStringFromUrls;
    }
}
