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

package net.sf.acegisecurity.ui.webapp;

import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.AuthenticationException;
import net.sf.acegisecurity.AuthenticationManager;
import net.sf.acegisecurity.providers.UsernamePasswordAuthenticationToken;

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
 * Processes an authentication form, putting the result into the
 * <code>HttpSession</code>.
 * 
 * <p>
 * This filter is responsible for processing authentication requests. A user
 * will typically authenticate once using a login form, and this filter
 * processes that form. If authentication is successful, the resulting {@link
 * Authentication} object will be placed into the <code>HttpSession</code>
 * with the attribute defined by {@link
 * HttpSessionIntegrationFilter#ACEGI_SECURITY_AUTHENTICATION_KEY}.
 * </p>
 * 
 * <p>
 * Login forms must present two parameters to this filter: a username and
 * password. The filter will process the login against the authentication
 * environment that was configured from a Spring application context defined
 * in the filter initialization.
 * </p>
 * 
 * <p>
 * If authentication fails, the <code>AuthenticationException</code> will be
 * placed into the <code>HttpSession</code> with the attribute defined by
 * {@link #ACEGI_SECURITY_LAST_EXCEPTION_KEY}.
 * </p>
 * 
 * <p>
 * This filter works with an {@link AuthenticationManager} which is used to
 * process each authentication request. By default, at init time, the filter
 * will use Spring's {@link
 * WebApplicationContextUtils#getWebApplicationContext(ServletContext sc)}
 * method to obtain an ApplicationContext instance, inside which must be a
 * configured AuthenticationManager instance. In the case where it is
 * desirable for  this filter to instantiate its own ApplicationContext
 * instance from which to obtain the AuthenticationManager, the location of
 * the config for this context may be specified with the optional
 * <code>appContextLocation</code> init param.
 * </p>
 * 
 * <p>
 * To use this filter, it is necessary to specify the following filter
 * initialization parameters:
 * </p>
 * 
 * <ul>
 * <li>
 * <code>defaultTargetUrl</code> indicates the URL that should be used for
 * redirection if the <code>HttpSession</code> attribute named {@link
 * #ACEGI_SECURITY_TARGET_URL_KEY} does not indicate the target URL once
 * authentication is completed successfully. eg: <code>/</code>.
 * </li>
 * <li>
 * <code>authenticationFailureUrl</code> indicates the URL that should be used
 * for redirection if the authentication request fails. eg:
 * <code>/login.jsp?login_error=1</code>.
 * </li>
 * <li>
 * <code>filterProcessesUrl</code> indicates the URL that this filter will
 * respond to. This parameter is optional, and defaults to
 * <code>/j_acegi_security_check</code>.
 * </li>
 * <li>
 * <code>contextConfigLocation</code> (optional, normally not used), indicates the
 * path to an application context that contains an {@link
 * AuthenticationManager} which should be used to process each authentication
 * request. If not specified, {@link
 * WebApplicationContextUtils#getWebApplicationContext(ServletContext sc)}
 * will be used to obtain the context.
 * </li>
 * </ul>
 * 
 *
 * @author Ben Alex
 * @author Colin Sampaleanu
 * @version $Id$
 */
public class AuthenticationProcessingFilter implements Filter {
    //~ Static fields/initializers =============================================

    /**
     * Name of (optional) servlet filter parameter that can specify the config
     * location for a new ApplicationContext used to config this filter.
     */
    public static final String CONFIG_LOCATION_PARAM = "contextConfigLocation";
    public static final String ACEGI_SECURITY_TARGET_URL_KEY = "ACEGI_SECURITY_TARGET_URL";
    public static final String ACEGI_SECURITY_FORM_USERNAME_KEY = "j_username";
    public static final String ACEGI_SECURITY_FORM_PASSWORD_KEY = "j_password";
    public static final String ACEGI_SECURITY_LAST_EXCEPTION_KEY = "ACEGI_SECURITY_LAST_EXCEPTION";
    private static final Log logger = LogFactory.getLog(AuthenticationProcessingFilter.class);

    //~ Instance fields ========================================================

    private ApplicationContext ctx;
    private AuthenticationManager authenticationManager;

    /** Where to redirect the browser to if authentication fails */
    private String authenticationFailureUrl;

    /**
     * Where to redirect the browser to if authentication is successful but
     * ACEGI_SECURITY_TARGET_URL_KEY is <code>null</code>
     */
    private String defaultTargetUrl;

    /**
     * The URL destination that this filter intercepts and processes (usually
     * <code>/j_acegi_security_check</code>)
     */
    private String filterProcessesUrl;
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
            throw new ServletException("Can only process HttpServletRequest");
        }

        if (!(response instanceof HttpServletResponse)) {
            throw new ServletException("Can only process HttpServletResponse");
        }

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        if (filterProcessesUrl.equals(httpRequest.getServletPath())) {
            if (logger.isDebugEnabled()) {
                logger.debug("Request is to process Acegi login form");
            }

            String username = httpRequest.getParameter(ACEGI_SECURITY_FORM_USERNAME_KEY);
            String password = httpRequest.getParameter(ACEGI_SECURITY_FORM_PASSWORD_KEY);

            if (username == null) {
                username = "";
            }

            if (password == null) {
                password = "";
            }

            UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(username,
                    password);

            Authentication authResult;

            try {
                authResult = authenticationManager.authenticate(authRequest);
            } catch (AuthenticationException failed) {
                // Authentication failed
                if (logger.isDebugEnabled()) {
                    logger.debug("Authentication request for user: " + username
                        + " failed: " + failed.toString());
                }

                httpRequest.getSession().setAttribute(ACEGI_SECURITY_LAST_EXCEPTION_KEY,
                    failed);
                httpRequest.getSession().setAttribute(HttpSessionIntegrationFilter.ACEGI_SECURITY_AUTHENTICATION_KEY,
                    null);
                httpResponse.sendRedirect(httpRequest.getContextPath()
                    + authenticationFailureUrl);

                return;
            }

            // Authentication success
            if (logger.isDebugEnabled()) {
                logger.debug("Authentication success: " + authResult.toString());
            }

            httpRequest.getSession().setAttribute(HttpSessionIntegrationFilter.ACEGI_SECURITY_AUTHENTICATION_KEY,
                authResult);

            String targetUrl = (String) httpRequest.getSession().getAttribute(AuthenticationProcessingFilter.ACEGI_SECURITY_TARGET_URL_KEY);
            httpRequest.getSession().setAttribute(AuthenticationProcessingFilter.ACEGI_SECURITY_TARGET_URL_KEY,
                null);

            if (targetUrl == null) {
                targetUrl = defaultTargetUrl;
            }

            if (logger.isDebugEnabled()) {
                logger.debug(
                    "Redirecting to target URL from HTTP Session (or default): "
                    + targetUrl);
            }

            httpResponse.sendRedirect(httpRequest.getContextPath() + targetUrl);

            return;
        }

        chain.doFilter(request, response);
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

        defaultTargetUrl = filterConfig.getInitParameter("defaultTargetUrl");

        if ((defaultTargetUrl == null) || "".equals(defaultTargetUrl)) {
            throw new ServletException("defaultTargetUrl must be specified");
        }

        authenticationFailureUrl = filterConfig.getInitParameter(
                "authenticationFailureUrl");

        if ((authenticationFailureUrl == null)
            || "".equals(authenticationFailureUrl)) {
            throw new ServletException(
                "authenticationFailureUrl must be specified");
        }

        filterProcessesUrl = filterConfig.getInitParameter("filterProcessesUrl");

        if ((filterProcessesUrl == null) || "".equals(filterProcessesUrl)) {
            filterProcessesUrl = "/j_acegi_security_check";
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

        Map beans = ctx.getBeansOfType(AuthenticationManager.class, true, true);

        if (beans.size() == 0) {
            throw new ServletException(
                "Bean context must contain at least one bean of type AuthenticationManager");
        }

        String beanName = (String) beans.keySet().iterator().next();
        authenticationManager = (AuthenticationManager) beans.get(beanName);
    }
}
