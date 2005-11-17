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

package org.acegisecurity.adapters.cas;

import edu.yale.its.tp.cas.auth.PasswordHandler;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.context.ApplicationContext;

import org.springframework.web.context.support.WebApplicationContextUtils;

import java.util.Map;

import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;


/**
 * Enables CAS to use the Acegi Security System for authentication.
 * 
 * <P>
 * This class works along with {@link CasPasswordHandler} to enable users to
 * easily migrate from stand-alone Acegi Security System deployments to
 * enterprise-wide CAS deployments.
 * </p>
 * 
 * <p>
 * It should be noted that the Acegi Security System will operate as a CAS
 * client irrespective of the <code>PasswordHandler</code> used on the CAS
 * server. In other words, this class need <B>not</B> be used on the CAS
 * server if not desired. It exists solely for the convenience of users
 * wishing have CAS delegate to an Acegi Security System-based
 * <code>AuthenticationManager</code>.
 * </p>
 * 
 * <p>
 * This class works requires a properly configured
 * <code>CasPasswordHandler</code>. On the first authentication request, the
 * class will use Spring's {@link
 * WebApplicationContextUtils#getWebApplicationContext(ServletContext sc)}
 * method to obtain an <code>ApplicationContext</code> instance, inside which
 * must be a configured <code>CasPasswordHandler</code> instance. The
 * <code>CasPasswordHandlerProxy</code> will then delegate authentication
 * requests to that instance.
 * </p>
 * 
 * <p>
 * To configure CAS to use this class, edit CAS' <code>web.xml</code> and
 * define the <code>edu.yale.its.tp.cas.authHandler</code> context parameter
 * with the value
 * <code>org.acegisecurity.adapters.cas.CasPasswordHandlerProxy</code>.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class CasPasswordHandlerProxy implements PasswordHandler {
    //~ Static fields/initializers =============================================

    private static final Log logger = LogFactory.getLog(CasPasswordHandlerProxy.class);

    //~ Instance fields ========================================================

    private ApplicationContext ctx;
    private CasPasswordHandler handler;

    //~ Methods ================================================================

    /**
     * Called by CAS when authentication is required.
     * 
     * <P>
     * Delegates to the <code>CasPasswordHandler</code>.
     * </p>
     *
     * @param request as provided by CAS
     * @param username provided to CAS
     * @param password provided to CAS
     *
     * @return whether authentication was successful or not
     *
     * @throws IllegalArgumentException if the application context does not
     *         contain a <code>CasPasswordHandler</code> or the
     *         <code>ServletRequest</code> was not of type
     *         <code>HttpServletRequest</code>
     */
    public boolean authenticate(ServletRequest request, String username,
        String password) {
        if (ctx == null) {
            if (!(request instanceof HttpServletRequest)) {
                throw new IllegalArgumentException(
                    "Can only process HttpServletRequest");
            }

            HttpServletRequest httpRequest = (HttpServletRequest) request;

            ctx = this.getContext(httpRequest);
        }

        if (handler == null) {
            Map beans = ctx.getBeansOfType(CasPasswordHandler.class, true, true);

            if (beans.size() == 0) {
                throw new IllegalArgumentException(
                    "Bean context must contain at least one bean of type CasPasswordHandler");
            }

            String beanName = (String) beans.keySet().iterator().next();
            handler = (CasPasswordHandler) beans.get(beanName);
        }

        return handler.authenticate(request, username, password);
    }

    /**
     * Allows test cases to override where application context obtained from.
     *
     * @param httpRequest which can be used to find the
     *        <code>ServletContext</code>
     *
     * @return the Spring application context
     */
    protected ApplicationContext getContext(HttpServletRequest httpRequest) {
        return WebApplicationContextUtils.getRequiredWebApplicationContext(httpRequest.getSession()
                                                                                      .getServletContext());
    }
}
