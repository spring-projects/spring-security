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

package net.sf.acegisecurity.ui;

import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.AuthenticationException;
import net.sf.acegisecurity.AuthenticationManager;
import net.sf.acegisecurity.AuthenticationServiceException;
import net.sf.acegisecurity.BadCredentialsException;
import net.sf.acegisecurity.DisabledException;
import net.sf.acegisecurity.LockedException;
import net.sf.acegisecurity.providers.cas.ProxyUntrustedException;
import net.sf.acegisecurity.ui.webapp.HttpSessionIntegrationFilter;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.factory.InitializingBean;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


/**
 * Abstract processor of HTTP-based authentication requests, which places the
 * resulting <code>Authentication</code> object into the
 * <code>HttpSession</code>.
 * 
 * <p>
 * This filter is responsible for processing authentication requests. If
 * authentication is successful, the resulting {@link Authentication} object
 * will be placed into the <code>HttpSession</code> with the attribute defined
 * by {@link HttpSessionIntegrationFilter#ACEGI_SECURITY_AUTHENTICATION_KEY}.
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
 * authentication is completed successfully. eg: <code>/</code>. This will be
 * treated as relative to the web-app's context path, and should include the
 * leading <code>/</code>.
 * </li>
 * <li>
 * <code>authenticationFailureUrl</code> indicates the URL that should be used
 * for redirection if the authentication request fails. eg:
 * <code>/login.jsp?login_error=1</code>.
 * </li>
 * <li>
 * <code>filterProcessesUrl</code> indicates the URL that this filter will
 * respond to. This parameter varies by subclass.
 * </li>
 * <li>
 * <code>alwaysUseDefaultTargetUrl</code> causes successful authentication to
 * always redirect to the <code>defaultTargetUrl</code>, even if the
 * <code>HttpSession</code> attribute named {@link
 * #ACEGI_SECURITY_TARGET_URL_KEY} defines the intended target URL.
 * </li>
 * </ul>
 * 
 *
 * @author Ben Alex
 * @author colin sampaleanu
 * @version $Id$
 */
public abstract class AbstractProcessingFilter implements Filter,
    InitializingBean {
    //~ Static fields/initializers =============================================

    public static final String ACEGI_SECURITY_TARGET_URL_KEY = "ACEGI_SECURITY_TARGET_URL";
    public static final String ACEGI_SECURITY_LAST_EXCEPTION_KEY = "ACEGI_SECURITY_LAST_EXCEPTION";
    protected static final Log logger = LogFactory.getLog(AbstractProcessingFilter.class);

    //~ Instance fields ========================================================

    private AuthenticationManager authenticationManager;

    /**
     * Where to redirect the browser if authentication fails due to incorrect
     * credentials
     */
    private String authenticationCredentialCheckFailureUrl;

    /**
     * Where to redirect the browser if authentication fails due to the users
     * account being disabled
     */
    private String authenticationDisabledFailureUrl;

    /** Where to redirect the browser to if authentication fails */
    private String authenticationFailureUrl;

    /**
     * Where to redirect the browser if authentication fails due to the users
     * account being locked
     */
    private String authenticationLockedFailureUrl;

    /**
     * Where to redirect the browser if authentication fails due to the user's
     * proxy being considered untrusted
     */
    private String authenticationProxyUntrustedFailureUrl;

    /**
     * Where to redirect the browser if authentication fails due to failure of
     * the authentication service
     */
    private String authenticationServiceFailureUrl;

    /**
     * Where to redirect the browser to if authentication is successful but
     * ACEGI_SECURITY_TARGET_URL_KEY is <code>null</code>
     */
    private String defaultTargetUrl;

    /**
     * The URL destination that this filter intercepts and processes (usually
     * something like <code>/j_acegi_security_check</code>)
     */
    private String filterProcessesUrl = getDefaultFilterProcessesUrl();

    /**
     * If <code>true</code>, will always redirect to {@link #defaultTargetUrl}
     * upon successful authentication, irrespective of the page that caused
     * the authentication request (defualts to <code>false</code>).
     */
    private boolean alwaysUseDefaultTargetUrl = false;

    /**
     * Indicates if the filter chain should be continued prior to delegation to
     * {@link #successfulAuthentication(HttpServletRequest,
     * HttpServletResponse, Authentication)}, which may be useful in certain
     * environment (eg Tapestry). Defaults to <code>false</code>.
     */
    private boolean continueChainBeforeSuccessfulAuthentication = false;

    //~ Methods ================================================================

    public void setAlwaysUseDefaultTargetUrl(boolean alwaysUseDefaultTargetUrl) {
        this.alwaysUseDefaultTargetUrl = alwaysUseDefaultTargetUrl;
    }

    public boolean isAlwaysUseDefaultTargetUrl() {
        return alwaysUseDefaultTargetUrl;
    }

    public void setContinueChainBeforeSuccessfulAuthentication(
        boolean continueChainBeforeSuccessfulAuthentication) {
        this.continueChainBeforeSuccessfulAuthentication = continueChainBeforeSuccessfulAuthentication;
    }

    public boolean isContinueChainBeforeSuccessfulAuthentication() {
        return continueChainBeforeSuccessfulAuthentication;
    }

    /**
     * Specifies the default <code>filterProcessesUrl</code> for the
     * implementation.
     *
     * @return the default <code>filterProcessesUrl</code>
     */
    public abstract String getDefaultFilterProcessesUrl();

    /**
     * Performs actual authentication.
     *
     * @param request from which to extract parameters and perform the
     *        authentication
     *
     * @return the authenticated user
     *
     * @throws AuthenticationException if authentication fails
     */
    public abstract Authentication attemptAuthentication(
        HttpServletRequest request) throws AuthenticationException;

    public void setAuthenticationCredentialCheckFailureUrl(
        String authenticationCredentialCheckFailureUrl) {
        this.authenticationCredentialCheckFailureUrl = authenticationCredentialCheckFailureUrl;
    }

    public String getAuthenticationCredentialCheckFailureUrl() {
        return authenticationCredentialCheckFailureUrl;
    }

    public void setAuthenticationDisabledFailureUrl(
        String authenticationDisabledFailureUrl) {
        this.authenticationDisabledFailureUrl = authenticationDisabledFailureUrl;
    }

    public String getAuthenticationDisabledFailureUrl() {
        return authenticationDisabledFailureUrl;
    }

    public void setAuthenticationFailureUrl(String authenticationFailureUrl) {
        this.authenticationFailureUrl = authenticationFailureUrl;
    }

    public String getAuthenticationFailureUrl() {
        return authenticationFailureUrl;
    }

    public void setAuthenticationLockedFailureUrl(
        String authenticationLockedFailureUrl) {
        this.authenticationLockedFailureUrl = authenticationLockedFailureUrl;
    }

    public String getAuthenticationLockedFailureUrl() {
        return authenticationLockedFailureUrl;
    }

    public void setAuthenticationManager(
        AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    public AuthenticationManager getAuthenticationManager() {
        return authenticationManager;
    }

    public void setAuthenticationProxyUntrustedFailureUrl(
        String authenticationProxyUntrustedFailureUrl) {
        this.authenticationProxyUntrustedFailureUrl = authenticationProxyUntrustedFailureUrl;
    }

    public String getAuthenticationProxyUntrustedFailureUrl() {
        return authenticationProxyUntrustedFailureUrl;
    }

    public void setAuthenticationServiceFailureUrl(
        String authenticationServiceFailureUrl) {
        this.authenticationServiceFailureUrl = authenticationServiceFailureUrl;
    }

    public String getAuthenticationServiceFailureUrl() {
        return authenticationServiceFailureUrl;
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

        if (requiresAuthentication(httpRequest, httpResponse)) {
            if (logger.isDebugEnabled()) {
                logger.debug("Request is to process authentication");
            }

            onPreAuthentication(httpRequest, httpResponse);

            Authentication authResult;

            try {
                authResult = attemptAuthentication(httpRequest);
            } catch (AuthenticationException failed) {
                // Authentication failed
                unsuccessfulAuthentication(httpRequest, httpResponse, failed);

                return;
            }

            // Authentication success
            if (continueChainBeforeSuccessfulAuthentication) {
                chain.doFilter(request, response);
            }

            successfulAuthentication(httpRequest, httpResponse, authResult);

            return;
        }

        chain.doFilter(request, response);
    }

    protected void onPreAuthentication(HttpServletRequest request,
        HttpServletResponse response) throws IOException {}

    protected void onSuccessfulAuthentication(HttpServletRequest request,
        HttpServletResponse response) throws IOException {}

    protected void onUnsuccessfulAuthentication(HttpServletRequest request,
        HttpServletResponse response) throws IOException {}

    /**
     * Indicates whether this filter should attempt to process a login request
     * for the current invocation.
     * 
     * <p>
     * Subclasses may override for special requirements, such as Tapestry
     * integration.
     * </p>
     *
     * @param request as received from the filter chain
     * @param response as received from the filter chain
     *
     * @return <code>true</code> if the filter should attempt authentication,
     *         <code>false</code> otherwise
     */
    protected boolean requiresAuthentication(HttpServletRequest request,
        HttpServletResponse response) {
        return request.getRequestURL().toString().endsWith(request
            .getContextPath() + filterProcessesUrl);
    }

    protected void successfulAuthentication(HttpServletRequest request,
        HttpServletResponse response, Authentication authResult)
        throws IOException {
        if (logger.isDebugEnabled()) {
            logger.debug("Authentication success: " + authResult.toString());
        }

        request.getSession().setAttribute(HttpSessionIntegrationFilter.ACEGI_SECURITY_AUTHENTICATION_KEY,
            authResult);

        String targetUrl = (String) request.getSession().getAttribute(ACEGI_SECURITY_TARGET_URL_KEY);
        request.getSession().removeAttribute(ACEGI_SECURITY_TARGET_URL_KEY);

        if (alwaysUseDefaultTargetUrl == true) {
            targetUrl = null;
        }

        if (targetUrl == null) {
            targetUrl = request.getContextPath() + defaultTargetUrl;
        }

        if (logger.isDebugEnabled()) {
            logger.debug(
                "Redirecting to target URL from HTTP Session (or default): "
                + targetUrl);
        }

        onSuccessfulAuthentication(request, response);

        response.sendRedirect(response.encodeRedirectURL(targetUrl));
    }

    protected void unsuccessfulAuthentication(HttpServletRequest request,
        HttpServletResponse response, AuthenticationException failed)
        throws IOException {
        String failureUrl = authenticationFailureUrl;

        if (failed instanceof AuthenticationServiceException
            && (authenticationServiceFailureUrl != null)) {
            failureUrl = authenticationServiceFailureUrl;
        }

        if (failed instanceof BadCredentialsException
            && (this.authenticationCredentialCheckFailureUrl != null)) {
            failureUrl = authenticationCredentialCheckFailureUrl;
        }

        if (failed instanceof DisabledException
            && (authenticationDisabledFailureUrl != null)) {
            failureUrl = authenticationDisabledFailureUrl;
        }

        if (failed instanceof LockedException
            && (authenticationLockedFailureUrl != null)) {
            failureUrl = authenticationLockedFailureUrl;
        }

        if (failed instanceof ProxyUntrustedException
            && (authenticationProxyUntrustedFailureUrl != null)) {
            failureUrl = authenticationProxyUntrustedFailureUrl;
        }

        if (logger.isDebugEnabled()) {
            logger.debug("Authentication request failed: " + failed.toString());
        }

        request.getSession().setAttribute(ACEGI_SECURITY_LAST_EXCEPTION_KEY,
            failed);
        request.getSession().removeAttribute(HttpSessionIntegrationFilter.ACEGI_SECURITY_AUTHENTICATION_KEY);

        onUnsuccessfulAuthentication(request, response);

        response.sendRedirect(response.encodeRedirectURL(request.getContextPath()
                + failureUrl));
    }
}
