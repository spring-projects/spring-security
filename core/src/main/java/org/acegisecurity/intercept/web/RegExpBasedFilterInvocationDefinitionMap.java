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

package org.acegisecurity.intercept.web;

import org.acegisecurity.ConfigAttributeDefinition;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.Vector;
import java.util.regex.Pattern;
import java.util.regex.Matcher;


/**
 * Maintains a <code>List</code> of <code>ConfigAttributeDefinition</code>s associated with different HTTP request
 * URL regular expression patterns.<p>Regular expressions are used to match a HTTP request URL against a
 * <code>ConfigAttributeDefinition</code>.</p>
 *  <p>The order of registering the regular expressions using the {@link #addSecureUrl(String,
 * ConfigAttributeDefinition)} is very important. The system will identify the <b>first</b>  matching regular
 * expression for a given HTTP URL. It will not proceed to evaluate later regular expressions if a match has already
 * been found. Accordingly, the most specific regular expressions should be registered first, with the most general
 * regular expressions registered last.</p>
 *  <p>If no registered regular expressions match the HTTP URL, <code>null</code> is returned.</p>
 */
public class RegExpBasedFilterInvocationDefinitionMap extends AbstractFilterInvocationDefinitionSource
    implements FilterInvocationDefinition {
    //~ Static fields/initializers =====================================================================================

    private static final Log logger = LogFactory.getLog(RegExpBasedFilterInvocationDefinitionMap.class);

    //~ Instance fields ================================================================================================

    private List requestMap = new Vector();
    private boolean convertUrlToLowercaseBeforeComparison = false;

    //~ Methods ========================================================================================================

    public void addSecureUrl(String regExp, ConfigAttributeDefinition attr) {
        Pattern pattern = Pattern.compile(regExp);

        requestMap.add(new EntryHolder(pattern, attr));

        if (logger.isDebugEnabled()) {
            logger.debug("Added regular expression: " + regExp + "; attributes: " + attr);
        }
    }

    public Iterator getConfigAttributeDefinitions() {
        Set set = new HashSet();
        Iterator iter = requestMap.iterator();

        while (iter.hasNext()) {
            EntryHolder entryHolder = (EntryHolder) iter.next();
            set.add(entryHolder.getConfigAttributeDefinition());
        }

        return set.iterator();
    }

    public int getMapSize() {
        return this.requestMap.size();
    }

    public boolean isConvertUrlToLowercaseBeforeComparison() {
        return convertUrlToLowercaseBeforeComparison;
    }

    public ConfigAttributeDefinition lookupAttributes(String url) {
        Iterator iter = requestMap.iterator();

        if (isConvertUrlToLowercaseBeforeComparison()) {
            url = url.toLowerCase();

            if (logger.isDebugEnabled()) {
                logger.debug("Converted URL to lowercase, from: '" + url + "'; to: '" + url + "'");
            }
        }

        while (iter.hasNext()) {
            EntryHolder entryHolder = (EntryHolder) iter.next();

            Matcher matcher = entryHolder.getCompiledPattern().matcher(url);

            boolean matched = matcher.matches();

            if (logger.isDebugEnabled()) {
                logger.debug("Candidate is: '" + url + "'; pattern is " + entryHolder.getCompiledPattern()
                    + "; matched=" + matched);
            }

            if (matched) {
                return entryHolder.getConfigAttributeDefinition();
            }
        }

        return null;
    }

    public void setConvertUrlToLowercaseBeforeComparison(boolean convertUrlToLowercaseBeforeComparison) {
        this.convertUrlToLowercaseBeforeComparison = convertUrlToLowercaseBeforeComparison;
    }

    //~ Inner Classes ==================================================================================================

    protected class EntryHolder {
        private ConfigAttributeDefinition configAttributeDefinition;
        private Pattern compiledPattern;

        public EntryHolder(Pattern compiledPattern, ConfigAttributeDefinition attr) {
            this.compiledPattern = compiledPattern;
            this.configAttributeDefinition = attr;
        }

        protected EntryHolder() {
            throw new IllegalArgumentException("Cannot use default constructor");
        }

        public Pattern getCompiledPattern() {
            return compiledPattern;
        }

        public ConfigAttributeDefinition getConfigAttributeDefinition() {
            return configAttributeDefinition;
        }
    }
}
