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


/**
 * Abstract implementation of <Code>FilterInvocationDefinitionSource</code>.
 * <p>
 * Stores an ordered map of compiled URL paths to <tt>ConfigAttributeDefinition</tt>s and provides URL matching
 * against the items stored in this map using the confgured <tt>UrlMatcher</tt>.
 * <p>
 * The order of registering the regular expressions using the {@link #addSecureUrl(String,
 * ConfigAttributeDefinition)} is very important. The system will identify the <b>first</b>  matching regular
 * expression for a given HTTP URL. It will not proceed to evaluate later regular expressions if a match has already
 * been found. Accordingly, the most specific regular expressions should be registered first, with the most general
 * regular expressions registered last.
 *
 * @author Ben Alex
 * @author Luke Taylor
 * @version $Id$
 */
public abstract class AbstractFilterInvocationDefinitionSource implements FilterInvocationDefinitionSource {

    protected final Log logger = LogFactory.getLog(getClass());

    private Map requestMap = new LinkedHashMap();

    private UrlMatcher urlMatcher;

    protected AbstractFilterInvocationDefinitionSource(UrlMatcher urlMatcher) {
        this.urlMatcher = urlMatcher;
    }

    //~ Methods ========================================================================================================

    /**
     * Adds a URL-ConfigAttributeDefinition pair to the request map, first allowing the <tt>UrlMatcher</tt> to
     * process the pattern if required, using its <tt>compile</tt> method. The returned object will be used as the key
     * to the request map and will be passed back to the <tt>UrlMatcher</tt> when iterating through the map to find
     * a match for a particular URL.
     */
    public void addSecureUrl(String pattern, ConfigAttributeDefinition attr) {
        requestMap.put(urlMatcher.compile(pattern), attr);

        if (logger.isDebugEnabled()) {
            logger.debug("Added URL pattern: " + pattern + "; attributes: " + attr);
        }
    }

    public Iterator getConfigAttributeDefinitions() {
        return getRequestMap().values().iterator();
    }

    public ConfigAttributeDefinition getAttributes(Object object) throws IllegalArgumentException {
        if ((object == null) || !this.supports(object.getClass())) {
            throw new IllegalArgumentException("Object must be a FilterInvocation");
        }

        String url = ((FilterInvocation) object).getRequestUrl();

        return lookupAttributes(url);
    }

    /**
     * Performs the actual lookup of the relevant <code>ConfigAttributeDefinition</code> for the specified
     * <code>FilterInvocation</code>.
     * <p>
     * By default, iterates through the stored URL map and calls the
     * {@link UrlMatcher#pathMatchesUrl(Object path, String url)} method until a match is found.
     * <p>
     * Subclasses can override if required to perform any modifications to the URL.
     * <p>
     * Public visiblity so that tablibs or other view helper classes can access the
     * <code>ConfigAttributeDefinition</code> applying to a given URI pattern without needing to construct a mock
     * <code>FilterInvocation</code> and retrieving the attibutes via the {@link #getAttributes(Object)} method.
     *
     * @param url the URI to retrieve configuration attributes for
     *
     * @return the <code>ConfigAttributeDefinition</code> that applies to the specified <code>FilterInvocation</code>
     * or null if no match is foud
     */
    public ConfigAttributeDefinition lookupAttributes(String url) {
        if (urlMatcher.requiresLowerCaseUrl()) {
            url = url.toLowerCase();

            if (logger.isDebugEnabled()) {
                logger.debug("Converted URL to lowercase, from: '" + url + "'; to: '" + url + "'");
            }
        }

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
}
