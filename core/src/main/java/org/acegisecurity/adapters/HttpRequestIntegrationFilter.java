/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
 */

package net.sf.acegisecurity.adapters;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;


/**
 * Populates a {@link net.sf.acegisecurity.context.SecureContext} from the
 * container's <code>HttpServletRequest.getUserPrincipal()</code>.
 * 
 * <p>
 * See {@link AbstractIntegrationFilter} for further information.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class HttpRequestIntegrationFilter extends AbstractIntegrationFilter {
    //~ Static fields/initializers =============================================

    private static final Log logger = LogFactory.getLog(HttpRequestIntegrationFilter.class);

    //~ Methods ================================================================

    public Object extractFromContainer(ServletRequest request) {
        if (request instanceof HttpServletRequest) {
            return ((HttpServletRequest) request).getUserPrincipal();
        } else {
            return null;
        }
    }
}
