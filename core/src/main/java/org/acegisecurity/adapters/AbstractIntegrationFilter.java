/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
 */

package net.sf.acegisecurity.adapters;

import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.context.Context;
import net.sf.acegisecurity.context.ContextHolder;
import net.sf.acegisecurity.context.SecureContext;
import net.sf.acegisecurity.context.SecureContextImpl;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;


/**
 * Automatically populates a {@link net.sf.acegisecurity.context.SecureContext}
 * from a subclass-provided container source.
 * 
 * <p>
 * The container is expected to expose an {@link Authentication} object in a
 * well-known location. The <code>Authentication</code> object will have been
 * created by the container-specific Acegi Security System for Spring adapter.
 * </p>
 * 
 * <P>
 * Once the <code>Authentication</code> object has been extracted from the
 * well-known location, the interceptor handles putting it into the {@link
 * ContextHolder}. It then removes it once the filter chain has  completed.
 * </p>
 * 
 * <p>
 * This interceptor will not operate if the container does not provide an
 * <code>Authentication</code> object from its well-known location.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public abstract class AbstractIntegrationFilter implements Filter {
    //~ Static fields/initializers =============================================

    protected static final Log logger = LogFactory.getLog(AbstractIntegrationFilter.class);

    //~ Methods ================================================================

    public void destroy() {}

    public void doFilter(ServletRequest request, ServletResponse response,
                         FilterChain chain)
                  throws IOException, ServletException {
        // Populate authentication information
        Object extracted = this.extractFromContainer(request);

        if (extracted instanceof Authentication) {
            if (logger.isDebugEnabled()) {
                logger.debug("Authentication added to ContextHolder from container");
            }

            Authentication auth = (Authentication) extracted;

            // Get or create existing SecureContext
            SecureContext secureContext = null;

            if ((ContextHolder.getContext() == null)
                    || !(ContextHolder.getContext() instanceof SecureContext)) {
                secureContext = new SecureContextImpl();
            } else {
                secureContext = (SecureContext) ContextHolder.getContext();
            }

            // Add Authentication to SecureContext, and save
            secureContext.setAuthentication(auth);
            ContextHolder.setContext((Context) secureContext);
        } else {
            if (logger.isDebugEnabled()) {
                logger.debug("Authentication not added to ContextHolder (could not extract an authentication object from the container which is an instance of Authentication)");
            }
        }

        // Proceed with chain
        chain.doFilter(request, response);

        // Remove authentication information
        if ((ContextHolder.getContext() != null)
                && ContextHolder.getContext() instanceof SecureContext) {
            if (logger.isDebugEnabled()) {
                logger.debug("Removing Authentication from ContextHolder");
            }

            // Get context holder and remove authentication information
            SecureContext secureContext = (SecureContext) ContextHolder
                                          .getContext();
            secureContext.setAuthentication(null);
            ContextHolder.setContext((Context) secureContext);
        } else {
            if (logger.isDebugEnabled()) {
                logger.debug("ContextHolder does not contain any authentication information");
            }
        }
    }

    /**
     * Subclasses must override this method to provide the <code>Object</code>
     * that contains the <code>Authentication</code> interface.
     * 
     * <p>
     * For convenience we have allowed any <code>Object</code> to be  returned
     * by subclasses, as the abstract class will ensure class casting safety
     * and ignore objects that do not implement  <code>Authentication</code>.
     * </p>
     * 
     * <p>
     * If no authentication object is available, subclasses should return
     * <code>null</code>.
     * </p>
     * 
     * <p>
     * If the container can locate multiple authentication objects,  subclasses
     * should return the object that was created by the Acegi Security System
     * for Spring adapter (ie that implements <code>Authentication</code>).
     * </p>
     *
     * @param request the request, which may be of use in extracting the
     *        authentication object
     *
     * @return <code>null</code> or an object that implements
     *         <code>Authentication</code>
     */
    public abstract Object extractFromContainer(ServletRequest request);

    public void init(FilterConfig filterConfig) throws ServletException {}
}
