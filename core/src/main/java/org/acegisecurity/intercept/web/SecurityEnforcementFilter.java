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

package net.sf.acegisecurity.intercept.web;

import net.sf.acegisecurity.AccessDeniedException;
import net.sf.acegisecurity.AuthenticationException;
import net.sf.acegisecurity.ui.webapp.AuthenticationProcessingFilter;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.context.support.ClassPathXmlApplicationContext;

import java.io.IOException;

import java.util.Map;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


/**
 * Wraps requests to the {@link FilterSecurityInterceptor}.
 * 
 * <P>
 * This filter is necessary because it provides an application context
 * environment for the <code>FilterSecurityInterceptor</code> instance.
 * </p>
 * 
 * <P>
 * If a {@link AuthenticationException} is detected, the filter will redirect
 * to the <code>loginFormUrl</code>. This allows common handling of
 * authentication failures originating from any subclass of {@link
 * net.sf.acegisecurity.intercept.AbstractSecurityInterceptor}.
 * </p>
 * 
 * <p>
 * If an {@link AccessDeniedException} is detected, the filter will response
 * with a <code>HttpServletResponse.SC_FORBIDDEN</code> (403 error). Again,
 * this allows common access denied handling irrespective of the originating
 * security interceptor.
 * </p>
 * 
 * <P>
 * To use this filter, it is necessary to specify the following filter
 * initialization parameters:
 * 
 * <ul>
 * <li>
 * <code>appContextLocation</code> indicates the path to an application context
 * that contains the <code>FilterSecurityInterceptor</code>.
 * </li>
 * <li>
 * <code>loginFormUrl</code> indicates the URL that should be used for
 * redirection if an <code>AuthenticationException</code> is detected.
 * </li>
 * </ul>
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class SecurityEnforcementFilter implements Filter {
    //~ Static fields/initializers =============================================

    private static final Log logger = LogFactory.getLog(SecurityEnforcementFilter.class);

    //~ Instance fields ========================================================

    protected ClassPathXmlApplicationContext ctx;
    protected FilterSecurityInterceptor securityInterceptor;

    /**
     * The URL that should be used for redirection if an
     * <code>AuthenticationException</code> is detected.
     */
    protected String loginFormUrl;

    //~ Methods ================================================================

    public void destroy() {
        ctx.close();
    }

    public void doFilter(ServletRequest request, ServletResponse response,
        FilterChain chain) throws IOException, ServletException {
        if (!(request instanceof HttpServletRequest)) {
            throw new ServletException("HttpServletRequest required");
        }

        if (!(response instanceof HttpServletResponse)) {
            throw new ServletException("HttpServletResponse required");
        }

        FilterInvocation fi = new FilterInvocation(request, response, chain);

        try {
            securityInterceptor.invoke(fi);

            if (logger.isDebugEnabled()) {
                logger.debug("Chain processed normally");
            }
        } catch (AuthenticationException authentication) {
            HttpServletRequest httpRequest = (HttpServletRequest) request;

            if (logger.isDebugEnabled()) {
                logger.debug(
                    "Authentication failed - adding target URL to Session: "
                    + fi.getRequestUrl());
            }

            ((HttpServletRequest) request).getSession().setAttribute(AuthenticationProcessingFilter.ACEGI_SECURITY_TARGET_URL_KEY,
                fi.getRequestUrl());
            ((HttpServletResponse) response).sendRedirect(((HttpServletRequest) request)
                .getContextPath() + loginFormUrl);
        } catch (AccessDeniedException accessDenied) {
            if (logger.isDebugEnabled()) {
                logger.debug(
                    "Access is denied - sending back forbidden response");
            }

            ((HttpServletResponse) response).sendError(HttpServletResponse.SC_FORBIDDEN); // 403
        } catch (Throwable otherException) {
            throw new ServletException(otherException);
        }
    }

    public void init(FilterConfig filterConfig) throws ServletException {
        String appContextLocation = filterConfig.getInitParameter(
                "appContextLocation");

        if ((appContextLocation == null) || "".equals(appContextLocation)) {
            throw new ServletException("appContextLocation must be specified");
        }

        if (Thread.currentThread().getContextClassLoader().getResource(appContextLocation) == null) {
            throw new ServletException("Cannot locate " + appContextLocation);
        }

        loginFormUrl = filterConfig.getInitParameter("loginFormUrl");

        if ((loginFormUrl == null) || "".equals(loginFormUrl)) {
            throw new ServletException("loginFormUrl must be specified");
        }

        ctx = new ClassPathXmlApplicationContext(appContextLocation);

        Map beans = ctx.getBeansOfType(FilterSecurityInterceptor.class, true,
                true);

        if (beans.size() == 0) {
            throw new ServletException(
                "Bean context must contain at least one bean of type FilterSecurityInterceptor");
        }

        String beanName = (String) beans.keySet().iterator().next();
        securityInterceptor = (FilterSecurityInterceptor) beans.get(beanName);
    }
}
