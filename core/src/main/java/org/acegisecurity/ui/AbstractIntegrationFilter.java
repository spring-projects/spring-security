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

package net.sf.acegisecurity.ui;

import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.context.Context;
import net.sf.acegisecurity.context.ContextHolder;
import net.sf.acegisecurity.context.SecureContext;
import net.sf.acegisecurity.context.SecureContextImpl;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.factory.InitializingBean;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;


/**
 * Automatically populates a {@link net.sf.acegisecurity.context.SecureContext}
 * from a subclass-provided <code>Authentication</code> object.
 * 
 * <p>
 * The container hosting the Acegi Security System for Spring secured
 * application is expected to expose an {@link Authentication} object in a
 * well-known location. The <code>Authentication</code> object will have been
 * created by the Acegi Security System for Spring and placed into the
 * well-known location via approaches such as container adapters or container
 * sessions.
 * </p>
 * 
 * <P>
 * Once the <code>Authentication</code> object has been extracted from the
 * well-known location, the <code>AbstractIntegrationFilter</code> handles
 * putting it into the {@link ContextHolder}. It then removes it once the
 * filter chain has completed.
 * </p>
 * 
 * <p>
 * This filter will not abort if an <code>Authentication</code> object cannot
 * be obtained from the well-known location. It will simply continue the
 * filter chain as normal.
 * </p>
 * 
 * <p>
 * If the <code>ContextHolder</code> does not contain a valid {@link
 * SecureContext}, one will be created. The created object will be of the
 * instance defined by the {@link #setSecureContext(Class)} method.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public abstract class AbstractIntegrationFilter implements InitializingBean,
    Filter {
    //~ Static fields/initializers =============================================

    protected static final Log logger = LogFactory.getLog(AbstractIntegrationFilter.class);

    //~ Instance fields ========================================================

    private Class secureContext = SecureContextImpl.class;

    //~ Methods ================================================================

    public void setSecureContext(Class secureContext) {
        this.secureContext = secureContext;
    }

    public Class getSecureContext() {
        return secureContext;
    }

    public void afterPropertiesSet() throws Exception {
        if ((this.secureContext == null)
            || (!this.secureContext.isAssignableFrom(SecureContext.class))) {
            throw new IllegalArgumentException(
                "secureContext must be defined and implement SecureContext");
        }
    }

    /**
     * Writes a new <code>Authentication</code> object to the container's
     * well-known location, if supported the subclass.
     *
     * @param request which may be required by the implementing method to
     *        access the well-known location for the current principal
     * @param authentication the new object to be written to the container
     */
    public abstract void commitToContainer(ServletRequest request,
        Authentication authentication);

    public void destroy() {}

    public void doFilter(ServletRequest request, ServletResponse response,
        FilterChain chain) throws IOException, ServletException {
        // Populate authentication information
        Object extracted = this.extractFromContainer(request);

        if (extracted instanceof Authentication) {
            if (logger.isDebugEnabled()) {
                logger.debug(
                    "Authentication added to ContextHolder from container");
            }

            Authentication auth = (Authentication) extracted;

            // Get or create existing SecureContext
            SecureContext sc = null;

            if ((ContextHolder.getContext() == null)
                || !(ContextHolder.getContext() instanceof SecureContext)) {
                try {
                    sc = (SecureContext) this.secureContext.newInstance();
                } catch (InstantiationException ie) {
                    throw new ServletException(ie);
                } catch (IllegalAccessException iae) {
                    throw new ServletException(iae);
                }
            } else {
                sc = (SecureContext) ContextHolder.getContext();
            }

            // Add Authentication to SecureContext, and save
            sc.setAuthentication(auth);
            ContextHolder.setContext((Context) sc);
        } else {
            if (logger.isDebugEnabled()) {
                logger.debug(
                    "Authentication not added to ContextHolder (could not extract an authentication object from the container which is an instance of Authentication)");
            }
        }

        // Proceed with chain
        chain.doFilter(request, response);

        // Remove authentication information
        if ((ContextHolder.getContext() != null)
            && ContextHolder.getContext() instanceof SecureContext) {
            if (logger.isDebugEnabled()) {
                logger.debug(
                    "Updating container with new Authentication object, and then removing Authentication from ContextHolder");
            }

            // Get context holder
            SecureContext secureContext = (SecureContext) ContextHolder
                .getContext();

            // Update container with new Authentication object (may have been updated during method invocation)
            this.commitToContainer(request, secureContext.getAuthentication());

            // Remove authentication information from ContextHolder
            secureContext.setAuthentication(null);
            ContextHolder.setContext((Context) secureContext);
        } else {
            if (logger.isDebugEnabled()) {
                logger.debug(
                    "ContextHolder does not contain any authentication information");
            }
        }
    }

    /**
     * Subclasses must override this method to provide the <code>Object</code>
     * that contains the <code>Authentication</code> interface.
     * 
     * <p>
     * For convenience we have allowed any <code>Object</code> to be returned
     * by subclasses, as the abstract class will ensure class casting safety
     * and ignore objects that do not implement <code>Authentication</code>.
     * </p>
     * 
     * <p>
     * If no <code>Authentication</code> object is available, subclasses should
     * return <code>null</code>.
     * </p>
     * 
     * <p>
     * If the subclass can locate multiple authentication objects, they should
     * return the object that was created by the Acegi Security System for
     * Spring (ie the object that implements <code>Authentication</code>).
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
