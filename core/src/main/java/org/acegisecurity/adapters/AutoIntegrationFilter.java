/* Copyright 2004 Acegi Technology Pty Limited
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

package net.sf.acegisecurity.adapters;

import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.adapters.jboss.JbossIntegrationFilter;

import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;


/**
 * Detects the container and delegates to the appropriate {@link
 * AbstractIntegrationFilter}.
 * 
 * <p>
 * This eases the creation of portable secured Spring applications, as the
 * <code>web.xml</code> will not need to refer to a specific container
 * integration filter.
 * </p>
 * 
 * <P>
 * The filter automatically delegates to
 * <code>HttpRequestIntegrationFilter</code> if any
 * <code>Authentication</code> object is detected in the
 * <code>ServletRequest</code>. Failing this, it will delegate to
 * <code>JbossIntegrationFilter</code> if the <code>ServletRequest</code>
 * contains an instance of JBoss' <code>SimplePrincipal</code>.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 *
 * @see AbstractIntegrationFilter
 */
public class AutoIntegrationFilter extends AbstractIntegrationFilter {
    //~ Methods ================================================================

    public Object extractFromContainer(ServletRequest request) {
        if (request instanceof HttpServletRequest) {
            HttpServletRequest httpRequest = (HttpServletRequest) request;

            if (httpRequest.getUserPrincipal() instanceof Authentication) {
                return getHttpServletRequest().extractFromContainer(request);
            }

            try {
                Class simplePrincipalClass = Class.forName(
                        "org.jboss.security.SimplePrincipal");

                if (null != httpRequest.getUserPrincipal()) {
                    if (simplePrincipalClass.isAssignableFrom(
                            httpRequest.getUserPrincipal().getClass())) {
                        return getJbossIntegrationFilter().extractFromContainer(request);
                    }
                }
            } catch (ClassNotFoundException e) {
                // Can't be JBoss principal
                // Expected, and normal - fall through
            }
        }

        return null;
    }

    /**
     * Allows test case to override the source of
     * <code>HttpRequestIntegrationFilter</code>.
     *
     * @return the <code>HttpRequestIntegrationFilter</code> to use
     */
    protected HttpRequestIntegrationFilter getHttpServletRequest() {
        return new HttpRequestIntegrationFilter();
    }

    /**
     * Allows test case to override the source of
     * <code>JbossIntegrationFilter</code>.
     *
     * @return the <code>JbossIntegrationFilter</code> to use
     */
    protected JbossIntegrationFilter getJbossIntegrationFilter() {
        return new JbossIntegrationFilter();
    }
}
