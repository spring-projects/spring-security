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

package org.acegisecurity.intercept.web;

import org.acegisecurity.ConfigAttributeDefinition;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.util.PathMatcher;
import org.springframework.util.AntPathMatcher;

import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.Vector;


/**
 * Maintains a <code>List</code> of <code>ConfigAttributeDefinition</code>s
 * associated with different HTTP request URL Apache Ant path-based patterns.
 * 
 * <p>
 * Apache Ant path expressions are used to match a HTTP request URL against a
 * <code>ConfigAttributeDefinition</code>.
 * </p>
 * 
 * <p>
 * The order of registering the Ant paths using the {@link
 * #addSecureUrl(String, ConfigAttributeDefinition)} is very important. The
 * system will identify the <b>first</b>  matching path for a given HTTP URL.
 * It will not proceed to evaluate later paths if a match has already been
 * found. Accordingly, the most specific paths should be registered first,
 * with the most general paths registered last.
 * </p>
 * 
 * <p>
 * If no registered paths match the HTTP URL, <code>null</code> is returned.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class PathBasedFilterInvocationDefinitionMap
    extends AbstractFilterInvocationDefinitionSource
    implements FilterInvocationDefinitionMap {
    //~ Static fields/initializers =============================================

    private static final Log logger = LogFactory.getLog(PathBasedFilterInvocationDefinitionMap.class);

    //~ Instance fields ========================================================

    private List requestMap = new Vector();
    private boolean convertUrlToLowercaseBeforeComparison = false;
    private PathMatcher pathMatcher = new AntPathMatcher();

    //~ Methods ================================================================

    public Iterator getConfigAttributeDefinitions() {
        Set set = new HashSet();
        Iterator iter = requestMap.iterator();

        while (iter.hasNext()) {
            EntryHolder entryHolder = (EntryHolder) iter.next();
            set.add(entryHolder.getConfigAttributeDefinition());
        }

        return set.iterator();
    }

    public void setConvertUrlToLowercaseBeforeComparison(
        boolean convertUrlToLowercaseBeforeComparison) {
        this.convertUrlToLowercaseBeforeComparison = convertUrlToLowercaseBeforeComparison;
    }

    public boolean isConvertUrlToLowercaseBeforeComparison() {
        return convertUrlToLowercaseBeforeComparison;
    }

    public int getMapSize() {
        return this.requestMap.size();
    }

    public void addSecureUrl(String antPath, ConfigAttributeDefinition attr) {
        requestMap.add(new EntryHolder(antPath, attr));

        if (logger.isDebugEnabled()) {
            logger.debug("Added Ant path: " + antPath + "; attributes: " + attr);
        }
    }

    public ConfigAttributeDefinition lookupAttributes(String url) {
        Iterator iter = requestMap.iterator();

        if (convertUrlToLowercaseBeforeComparison) {
            url = url.toLowerCase();

            if (logger.isDebugEnabled()) {
                logger.debug("Converted URL to lowercase, from: '" + url
                    + "'; to: '" + url + "'");
            }
        }

        while (iter.hasNext()) {
            EntryHolder entryHolder = (EntryHolder) iter.next();

            boolean matched = pathMatcher.match(entryHolder.getAntPath(), url);

            if (logger.isDebugEnabled()) {
                logger.debug("Candidate is: '" + url + "'; pattern is "
                    + entryHolder.getAntPath() + "; matched=" + matched);
            }

            if (matched) {
                return entryHolder.getConfigAttributeDefinition();
            }
        }

        return null;
    }

    //~ Inner Classes ==========================================================

    protected class EntryHolder {
        private ConfigAttributeDefinition configAttributeDefinition;
        private String antPath;

        public EntryHolder(String antPath, ConfigAttributeDefinition attr) {
            this.antPath = antPath;
            this.configAttributeDefinition = attr;
        }

        protected EntryHolder() {
            throw new IllegalArgumentException("Cannot use default constructor");
        }

        public String getAntPath() {
            return antPath;
        }

        public ConfigAttributeDefinition getConfigAttributeDefinition() {
            return configAttributeDefinition;
        }
    }
}
