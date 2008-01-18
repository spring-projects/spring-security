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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.util.Iterator;
import java.util.regex.Pattern;

/**
 * Maintains a <code>List</code> of <code>ConfigAttributeDefinition</code>s associated with different HTTP request
 * URL regular expression patterns.
 * <p>
 * Regular expressions are used to match a HTTP request URL against a <code>ConfigAttributeDefinition</code>.
 * <p>
 * The order of registering the regular expressions using the {@link #addSecureUrl(String,
 * ConfigAttributeDefinition)} is very important. The system will identify the <b>first</b>  matching regular
 * expression for a given HTTP URL. It will not proceed to evaluate later regular expressions if a match has already
 * been found. Accordingly, the most specific regular expressions should be registered first, with the most general
 * regular expressions registered last.
 * <p>
 * If no registered regular expressions match the HTTP URL, <code>null</code> is returned.
 */
public class RegExpBasedFilterInvocationDefinitionMap extends AbstractFilterInvocationDefinitionSource
    implements FilterInvocationDefinition {
    //~ Static fields/initializers =====================================================================================

    private static final Log logger = LogFactory.getLog(RegExpBasedFilterInvocationDefinitionMap.class);

    //~ Methods ========================================================================================================

    public void addSecureUrl(String regExp, ConfigAttributeDefinition attr) {
        Pattern pattern = Pattern.compile(regExp);

        getRequestMap().put(pattern, attr);

        if (logger.isDebugEnabled()) {
            logger.debug("Added regular expression: " + regExp + "; attributes: " + attr);
        }
    }

    public Iterator getConfigAttributeDefinitions() {
        return getRequestMap().values().iterator();
    }

    public ConfigAttributeDefinition lookupAttributes(String url) {
        if (isConvertUrlToLowercaseBeforeComparison()) {
            url = url.toLowerCase();

            if (logger.isDebugEnabled()) {
                logger.debug("Converted URL to lowercase, from: '" + url + "'; to: '" + url + "'");
            }
        }

        Iterator patterns = getRequestMap().keySet().iterator();

        while (patterns.hasNext()) {
            Pattern p = (Pattern) patterns.next();
            boolean matched = p.matcher(url).matches();

            if (logger.isDebugEnabled()) {
                logger.debug("Candidate is: '" + url + "'; pattern is " + p.pattern() + "; matched=" + matched);
            }

            if (matched) {
                return (ConfigAttributeDefinition) getRequestMap().get(p);
            }
        }

        return null;
    }
}
