/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
 */

package net.sf.acegisecurity.adapters;

import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.adapters.jboss.JbossIntegrationFilter;

import org.jboss.security.SimplePrincipal;

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
 * <p>
 * See {@link AbstractIntegrationFilter} for further information.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class AutoIntegrationFilter extends AbstractIntegrationFilter {
    //~ Methods ================================================================

    public Object extractFromContainer(ServletRequest request) {
        if (request instanceof HttpServletRequest) {
            HttpServletRequest httpRequest = (HttpServletRequest) request;

            if (httpRequest.getUserPrincipal() instanceof Authentication) {
                return new HttpRequestIntegrationFilter().extractFromContainer(request);
            }

            if (httpRequest.getUserPrincipal() instanceof SimplePrincipal) {
                return new JbossIntegrationFilter().extractFromContainer(request);
            }
        }

        return null;
    }
}
