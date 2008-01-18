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

import org.springframework.util.AntPathMatcher;
import org.springframework.util.PathMatcher;

import java.util.Iterator;


/**
 * Maintains a <code>List</code> of <code>ConfigAttributeDefinition</code>s associated with different HTTP request
 * URL Apache Ant path-based patterns.<p>Apache Ant path expressions are used to match a HTTP request URL against a
 * <code>ConfigAttributeDefinition</code>.
 * <p>
 * The order of registering the Ant paths using the {@link #addSecureUrl(String,ConfigAttributeDefinition)} is
 * very important. The system will identify the <b>first</b>  matching path for a given HTTP URL. It will not proceed
 * to evaluate later paths if a match has already been found. Accordingly, the most specific paths should be
 * registered first, with the most general paths registered last.
 * <p>
 * If no registered paths match the HTTP URL, <code>null</code> is returned.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class PathBasedFilterInvocationDefinitionMap extends AbstractFilterInvocationDefinitionSource
        implements FilterInvocationDefinition {
    //~ Static fields/initializers =====================================================================================

    private static final Log logger = LogFactory.getLog(PathBasedFilterInvocationDefinitionMap.class);

    private PathMatcher pathMatcher = new AntPathMatcher();

    //~ Methods ========================================================================================================

    public void addSecureUrl(String antPath, ConfigAttributeDefinition attr) {
        // SEC-501: If using lower case comparison, we should convert the paths to lower case
        // as any upper case characters included by mistake will prevent the URL from ever being matched.
        if (isConvertUrlToLowercaseBeforeComparison()) {
            antPath = antPath.toLowerCase();
        }

        getRequestMap().put(antPath, attr);

        if (logger.isDebugEnabled()) {
            logger.debug("Added Ant path: " + antPath + "; attributes: " + attr);
        }
    }

    public Iterator getConfigAttributeDefinitions() {
        return getRequestMap().values().iterator();
    }

    public ConfigAttributeDefinition lookupAttributes(String url) {
        // Strip anything after a question mark symbol, as per SEC-161. See also SEC-321
        int firstQuestionMarkIndex = url.indexOf("?");

        if (firstQuestionMarkIndex != -1) {
            url = url.substring(0, firstQuestionMarkIndex);
        }

        if (isConvertUrlToLowercaseBeforeComparison()) {
            url = url.toLowerCase();

            if (logger.isDebugEnabled()) {
                logger.debug("Converted URL to lowercase, from: '" + url + "'; to: '" + url + "'");
            }
        }

        Iterator paths = getRequestMap().keySet().iterator();

        while (paths.hasNext()) {
            String path = (String) paths.next();

            boolean matched = pathMatcher.match(path, url);

            if (logger.isDebugEnabled()) {
                logger.debug("Candidate is: '" + url + "'; pattern is " + path + "; matched=" + matched);
            }

            if (matched) {
                return (ConfigAttributeDefinition) getRequestMap().get(path);
            }
        }

        return null;
    }
}
