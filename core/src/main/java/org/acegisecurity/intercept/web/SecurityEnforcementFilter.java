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

import org.springframework.context.ApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;

import org.springframework.web.context.support.WebApplicationContextUtils;

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
 * <p>
 * This filter is necessary because it provides the bridge between incoming
 * requests and the <code>FilterSecurityInterceptor</code> instance.
 * </p>
 * 
 * <p>
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
 * <p>
 * This filter works with a <code>FilterSecurityInterceptor</code> instance. By
 * default, at init time, the filter will use Spring's {@link
 * WebApplicationContextUtils#getWebApplicationContext(ServletContext sc)}
 * method to obtain an ApplicationContext instance, inside which must be a
 * configured <code>FilterSecurityInterceptor</code> instance. In the case
 * where it is desireable for this filter to instantiate its own
 * ApplicationContext instance from which to obtain the
 * <code>FilterSecurityInterceptor</code>, the location of the config for this
 * context may be specified with the optional
 * <code>contextConfigLocation</code> init param.
 * </p>
 * 
 * <p>
 * To use this filter, it is necessary to specify the following filter
 * initialization parameters:
 * </p>
 * 
 * <ul>
 * <li>
 * <code>loginFormUrl</code> indicates the URL that should be used for
 * redirection if an <code>AuthenticationException</code> is detected.
 * </li>
 * <li>
 * <code>contextConfigLocation</code> (optional, normally not used), indicates
 * the path to an application context that contains a  properly configured
 * <code>FilterSecurityInterceptor</code>. If not specified, {@link
 * WebApplicationContextUtils#getWebApplicationContext(ServletContext sc)}
 * will be used to obtain the context.
 * </li>
 * </ul>
 * 
 *
 * @author Ben Alex
 * @author colin sampaleanu
 * @version $Id$
 */
public class SecurityEnforcementFilter implements Filter {
    //~ Static fields/initializers =============================================

    /**
     * Name of (optional) servlet filter parameter that can specify the config
     * location for a new ApplicationContext used to config this filter.
     */
    public static final String CONFIG_LOCATION_PARAM = "contextConfigLocation";
    private static final Log logger = LogFactory.getLog(SecurityEnforcementFilter.class);

    //~ Instance fields ========================================================

    protected FilterSecurityInterceptor securityInterceptor;

    /**
     * The URL that should be used for redirection if an
     * <code>AuthenticationException</code> is detected.
     */
    protected String loginFormUrl;
    private ApplicationContext ctx;
    private boolean ourContext = false;

    //~ Methods ================================================================

    public void destroy() {
        if (ourContext && ctx instanceof ConfigurableApplicationContext) {
            ((ConfigurableApplicationContext) ctx).close();
        }
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
        String appContextLocation = filterConfig.getInitParameter(CONFIG_LOCATION_PARAM);

        if ((appContextLocation != null) && (appContextLocation.length() > 0)) {
            ourContext = true;

            if (Thread.currentThread().getContextClassLoader().getResource(appContextLocation) == null) {
                throw new ServletException("Cannot locate "
                    + appContextLocation);
            }
        }

        loginFormUrl = filterConfig.getInitParameter("loginFormUrl");

        if ((loginFormUrl == null) || "".equals(loginFormUrl)) {
            throw new ServletException("loginFormUrl must be specified");
        }

        try {
            if (!ourContext) {
                ctx = WebApplicationContextUtils
                    .getRequiredWebApplicationContext(filterConfig
                        .getServletContext());
            } else {
                ctx = new ClassPathXmlApplicationContext(appContextLocation);
            }
        } catch (RuntimeException e) {
            throw new ServletException(
                "Error obtaining/creating ApplicationContext for config. Must be stored in ServletContext, or optionally '"
                + CONFIG_LOCATION_PARAM
                + "' param may be used to allow creation of new context by this filter. See root error for additional details",
                e);
        }

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
