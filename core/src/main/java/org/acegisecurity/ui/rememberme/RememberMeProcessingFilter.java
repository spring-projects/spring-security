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

package net.sf.acegisecurity.ui.rememberme;

import net.sf.acegisecurity.context.SecurityContextHolder;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.factory.InitializingBean;

import org.springframework.util.Assert;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


/**
 * Detects if there is no <code>Authentication</code> object in the
 * <code>SecurityContext</code>, and populates it with a remember-me
 * authentication token if a {@link
 * net.sf.acegisecurity.ui.rememberme.RememberMeServices} implementation so
 * requests.
 * 
 * <p>
 * Concrete <code>RememberMeServices</code> implementations will have their
 * {@link
 * net.sf.acegisecurity.ui.rememberme.RememberMeServices#autoLogin(HttpServletRequest,
 * HttpServletResponse)} method called by this filter. The
 * <code>Authentication</code> or <code>null</code> returned by that method
 * will be placed into the <code>SecurityContext</code>.
 * </p>
 * 
 * <P>
 * <B>Do not use this class directly.</B> Instead configure
 * <code>web.xml</code> to use the {@link
 * net.sf.acegisecurity.util.FilterToBeanProxy}.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class RememberMeProcessingFilter implements Filter, InitializingBean {
    //~ Static fields/initializers =============================================

    private static final Log logger = LogFactory.getLog(RememberMeProcessingFilter.class);

    //~ Instance fields ========================================================

    private RememberMeServices rememberMeServices = new NullRememberMeServices();

    //~ Methods ================================================================

    public void setRememberMeServices(RememberMeServices rememberMeServices) {
        this.rememberMeServices = rememberMeServices;
    }

    public RememberMeServices getRememberMeServices() {
        return rememberMeServices;
    }

    public void afterPropertiesSet() throws Exception {
        Assert.notNull(rememberMeServices);
    }

    /**
     * Does nothing - we reply on IoC lifecycle services instead.
     */
    public void destroy() {}

    public void doFilter(ServletRequest request, ServletResponse response,
        FilterChain chain) throws IOException, ServletException {
        if (!(request instanceof HttpServletRequest)) {
            throw new ServletException("Can only process HttpServletRequest");
        }

        if (!(response instanceof HttpServletResponse)) {
            throw new ServletException("Can only process HttpServletResponse");
        }

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            SecurityContextHolder.getContext().setAuthentication(rememberMeServices
                .autoLogin(httpRequest, httpResponse));

            if (logger.isDebugEnabled()) {
                logger.debug(
                    "Replaced SecurityContextHolder with remember-me token: '"
                    + SecurityContextHolder.getContext().getAuthentication()
                    + "'");
            }
        } else {
            if (logger.isDebugEnabled()) {
                logger.debug(
                    "SecurityContextHolder not replaced with remember-me token, as SecurityContextHolder already contained: '"
                    + SecurityContextHolder.getContext().getAuthentication()
                    + "'");
            }
        }

        chain.doFilter(request, response);
    }

    /**
     * Does nothing - we reply on IoC lifecycle services instead.
     *
     * @param arg0 not used
     *
     * @throws ServletException not thrown
     */
    public void init(FilterConfig arg0) throws ServletException {}
}
