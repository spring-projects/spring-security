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

package org.acegisecurity.adapters;

import org.acegisecurity.Authentication;
import org.acegisecurity.context.SecurityContextHolder;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.IOException;

import java.security.Principal;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;


/**
 * Populates <code>SecurityContext</code> with the <code>Authentication</code>
 * obtained from the container's
 * <code>HttpServletRequest.getUserPrincipal()</code>.
 * 
 * <p>
 * Use this filter with container adapters only.
 * </p>
 * 
 * <p>
 * This filter <b>never</b> preserves the <code>Authentication</code> on the
 * <code>SecurityContext</code> - it is replaced every request.
 * </p>
 * 
 * <p>
 * See {@link org.acegisecurity.context.HttpSessionContextIntegrationFilter}
 * for further information.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class HttpRequestIntegrationFilter implements Filter {
    //~ Static fields/initializers =============================================

    private static final Log logger = LogFactory.getLog(HttpRequestIntegrationFilter.class);

    //~ Methods ================================================================

    /**
     * Does nothing. We use IoC container lifecycle services instead.
     */
    public void destroy() {}

    public void doFilter(ServletRequest request, ServletResponse response,
        FilterChain chain) throws IOException, ServletException {
        if (request instanceof HttpServletRequest) {
            Principal principal = ((HttpServletRequest) request)
                .getUserPrincipal();

            if ((principal != null) && principal instanceof Authentication) {
                SecurityContextHolder.getContext().setAuthentication((Authentication) principal);

                if (logger.isDebugEnabled()) {
                    logger.debug(
                        "SecurityContextHolder updated with Authentication from container: '"
                        + principal + "'");
                }
            } else {
                if (logger.isDebugEnabled()) {
                    logger.debug(
                        "SecurityContextHolder not set with new Authentication as Principal was: '"
                        + principal + "'");
                }
            }
        } else {
            throw new IllegalArgumentException(
                "Only HttpServletRequest is acceptable");
        }

        chain.doFilter(request, response);
    }

    /**
     * Does nothing. We use IoC container lifecycle services instead.
     *
     * @param arg0 ignored
     *
     * @throws ServletException ignored
     */
    public void init(FilterConfig arg0) throws ServletException {}
}
