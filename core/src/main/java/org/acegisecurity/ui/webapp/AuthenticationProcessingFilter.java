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

import org.springframework.beans.factory.InitializingBean;

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
 * To use this filter, it is necessary to specify the following properties:
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
 * </ul>
 * 
 * <P>
 * <B>Do not use this class directly.</B> Instead configure
 * <code>web.xml</code> to use the {@link
 * net.sf.acegisecurity.util.FilterToBeanProxy}.
 * </p>
 *
 * @author Ben Alex
 * @author Colin Sampaleanu
 * @version $Id$
 */
public class AuthenticationProcessingFilter implements Filter, InitializingBean {
    //~ Static fields/initializers =============================================

    public static final String ACEGI_SECURITY_TARGET_URL_KEY = "ACEGI_SECURITY_TARGET_URL";
    public static final String ACEGI_SECURITY_FORM_USERNAME_KEY = "j_username";
    public static final String ACEGI_SECURITY_FORM_PASSWORD_KEY = "j_password";
    public static final String ACEGI_SECURITY_LAST_EXCEPTION_KEY = "ACEGI_SECURITY_LAST_EXCEPTION";
    private static final Log logger = LogFactory.getLog(AuthenticationProcessingFilter.class);

    //~ Instance fields ========================================================

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
    private String filterProcessesUrl = "/j_acegi_security_check";

    //~ Methods ================================================================

    public void setAuthenticationFailureUrl(String authenticationFailureUrl) {
        this.authenticationFailureUrl = authenticationFailureUrl;
    }

    public String getAuthenticationFailureUrl() {
        return authenticationFailureUrl;
    }

    public void setAuthenticationManager(
        AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    public AuthenticationManager getAuthenticationManager() {
        return authenticationManager;
    }

    public void setDefaultTargetUrl(String defaultTargetUrl) {
        this.defaultTargetUrl = defaultTargetUrl;
    }

    public String getDefaultTargetUrl() {
        return defaultTargetUrl;
    }

    public void setFilterProcessesUrl(String filterProcessesUrl) {
        this.filterProcessesUrl = filterProcessesUrl;
    }

    public String getFilterProcessesUrl() {
        return filterProcessesUrl;
    }

    public void afterPropertiesSet() throws Exception {
        if ((filterProcessesUrl == null) || "".equals(filterProcessesUrl)) {
            throw new IllegalArgumentException(
                "filterProcessesUrl must be specified");
        }

        if ((defaultTargetUrl == null) || "".equals(defaultTargetUrl)) {
            throw new IllegalArgumentException(
                "defaultTargetUrl must be specified");
        }

        if ((authenticationFailureUrl == null)
            || "".equals(authenticationFailureUrl)) {
            throw new IllegalArgumentException(
                "authenticationFailureUrl must be specified");
        }

        if (authenticationManager == null) {
            throw new IllegalArgumentException(
                "authenticationManager must be specified");
        }
    }

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

    public void init(FilterConfig filterConfig) throws ServletException {}
}
