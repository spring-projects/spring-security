/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.ui.webapp;

import org.springframework.security.Authentication;
import org.springframework.security.AuthenticationException;

import org.springframework.security.context.HttpSessionContextIntegrationFilter;
import org.springframework.security.context.SecurityContext;

import org.springframework.security.providers.UsernamePasswordAuthenticationToken;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


/**
 * Extends Spring Security's AuthenticationProcessingFilter to pick up CA/Netegrity Siteminder headers.
 * <p>
 * Also provides a backup form-based authentication and the ability set source key names.
 * <p>
 * <b>Siteminder</b> must present two <b>headers</b> to this filter, a username and password. You must set the
 * header keys before this filter is used for authentication, otherwise Siteminder checks will be skipped. If the
 * Siteminder check is unsuccessful (i.e. if the headers are not found), then the form parameters will be checked (see
 * next paragraph). This allows applications to optionally function even when their Siteminder infrastructure is
 * unavailable, as is often the case during development.
 * <p>
 * <b>Login forms</b> must present two <b>parameters</b> to this filter: a username and password. If not
 * specified, the parameter names to use are contained in the static fields {@link #SPRING_SECURITY_FORM_USERNAME_KEY}
 * and {@link #SPRING_SECURITY_FORM_PASSWORD_KEY}.
 */
public class SiteminderAuthenticationProcessingFilter extends AuthenticationProcessingFilter {
    //~ Static fields/initializers =====================================================================================

    /** Log instance for debugging */
    private static final Log logger = LogFactory.getLog(SiteminderAuthenticationProcessingFilter.class);

    //~ Instance fields ================================================================================================

    /** Form password request key. */
    private String formPasswordParameterKey = null;

    /** Form username request key. */
    private String formUsernameParameterKey = null;

    /** Siteminder password header key. */
    private String siteminderPasswordHeaderKey = null;

    /** Siteminder username header key. */
    private String siteminderUsernameHeaderKey = null;

    //~ Constructors ===================================================================================================

    /**
     * Basic constructor.
     */
    public SiteminderAuthenticationProcessingFilter() {
        super();
    }

    //~ Methods ========================================================================================================

    /**
     *
     * @see org.springframework.security.ui.AbstractProcessingFilter#attemptAuthentication(javax.servlet.http.HttpServletRequest)
     */
    public Authentication attemptAuthentication(HttpServletRequest request)
        throws AuthenticationException {
        String username = null;
        String password = null;

        // Check the Siteminder headers for authentication info
        if ((siteminderUsernameHeaderKey != null) && (siteminderUsernameHeaderKey.length() > 0)
            && (siteminderPasswordHeaderKey != null) && (siteminderPasswordHeaderKey.length() > 0)) {
            username = request.getHeader(siteminderUsernameHeaderKey);
            password = request.getHeader(siteminderPasswordHeaderKey);
        }

        // If the Siteminder authentication info wasn't available, then get it
        // from the form parameters
        if ((username == null) || (username.length() == 0) || (password == null) || (password.length() == 0)) {
            if (logger.isDebugEnabled()) {
                logger.debug("Siteminder headers not found for authentication, so trying to use form values");
            }

            if ((formUsernameParameterKey != null) && (formUsernameParameterKey.length() > 0)) {
                username = request.getParameter(formUsernameParameterKey);
            } else {
                username = request.getParameter(SPRING_SECURITY_FORM_USERNAME_KEY);
            }

            password = obtainPassword(request);
        }

        // Convert username and password to upper case. This is normally not a
        // good practice but we do it here because Siteminder gives us the username
        // in lower case, while most backing systems store it in upper case.
        if (username != null) {
            username = username.toUpperCase();
        } else {
            // If username is null, set to blank to avoid a NPE.
            username = "";
        }

        if (password != null) {
            password = password.toUpperCase();
        } else {
            // If password is null, set to blank to avoid a NPE.
            password = "";
        }

        UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(username, password);

        // Allow subclasses to set the "details" property
        setDetails(request, authRequest);

        // Place the last username attempted into HttpSession for views
        request.getSession().setAttribute(SPRING_SECURITY_LAST_USERNAME_KEY, username);

        return this.getAuthenticationManager().authenticate(authRequest);
    }

    /**
     * Returns the form password parameter key.
     *
     * @return The form password parameter key.
     */
    public String getFormPasswordParameterKey() {
        return formPasswordParameterKey;
    }

    /**
     * Returns the form username parameter key.
     *
     * @return The form username parameter key.
     */
    public String getFormUsernameParameterKey() {
        return formUsernameParameterKey;
    }

    /**
     * Returns the Siteminder password header key.
     *
     * @return The Siteminder password header key.
     */
    public String getSiteminderPasswordHeaderKey() {
        return siteminderPasswordHeaderKey;
    }

    /**
     * Returns the Siteminder username header key.
     *
     * @return The Siteminder username header key.
     */
    public String getSiteminderUsernameHeaderKey() {
        return siteminderUsernameHeaderKey;
    }

    /**
     * Overridden method to obtain different value depending on whether Siteminder or form validation is being
     * performed.
     *
     * @param request so that request attributes can be retrieved
     *
     * @return the password that will be presented in the <code>Authentication</code> request token to the
     *         <code>AuthenticationManager</code>
     */
    protected String obtainPassword(HttpServletRequest request) {
        if ((formPasswordParameterKey != null) && (formPasswordParameterKey.length() > 0)) {
            return request.getParameter(formPasswordParameterKey);
        } else {
            return request.getParameter(SPRING_SECURITY_FORM_PASSWORD_KEY);
        }
    }

    /**
     * Overridden to perform authentication not only on j_security_check, but also on requests for the default
     * target URL when the user isn't already authenticated.<p>Thank you Paul Garvey for providing a
     * straightforward solution (and code) for this!</p>
     *
     * @see org.springframework.security.ui.AbstractProcessingFilter#requiresAuthentication(javax.servlet.http.HttpServletRequest,
     *      javax.servlet.http.HttpServletResponse)
     */
    protected boolean requiresAuthentication(final HttpServletRequest request, final HttpServletResponse response) {
        String uri = request.getRequestURI();
        int pathParamIndex = uri.indexOf(';');

        if (pathParamIndex > 0) {
            // strip everything after the first semi-colon
            uri = uri.substring(0, pathParamIndex);
        }

        //attempt authentication if j_secuity_check is present or if the getDefaultTargetUrl()
        //is present and user is not already authenticated.
        boolean bAuthenticated = false;
        SecurityContext context = (SecurityContext)
                request.getSession().getAttribute(HttpSessionContextIntegrationFilter.SPRING_SECURITY_CONTEXT_KEY);

        if (context != null) {
            Authentication auth = context.getAuthentication();

            if ((auth != null) && auth instanceof UsernamePasswordAuthenticationToken) {
                UsernamePasswordAuthenticationToken token = (UsernamePasswordAuthenticationToken) auth;
                bAuthenticated = token.isAuthenticated();
            }
        }

        // if true is returned then authentication will be attempted.
        boolean bAttemptAuthentication = (uri.endsWith(request.getContextPath() + getFilterProcessesUrl()))
                || ((getDefaultTargetUrl() != null) && uri.endsWith(getDefaultTargetUrl()) && !bAuthenticated);

        if (logger.isDebugEnabled()) {
            logger.debug("Authentication attempted for the following URI ==> " + uri + " is " + bAttemptAuthentication);
        }

        return bAttemptAuthentication;
    }

    /**
     * Sets the form password parameter key.
     *
     * @param key The form password parameter key.
     */
    public void setFormPasswordParameterKey(final String key) {
        this.formPasswordParameterKey = key;
    }

    /**
     * Sets the form username parameter key.
     *
     * @param key The form username parameter key.
     */
    public void setFormUsernameParameterKey(final String key) {
        this.formUsernameParameterKey = key;
    }

    /**
     * Sets the Siteminder password header key.
     *
     * @param key The Siteminder password header key.
     */
    public void setSiteminderPasswordHeaderKey(final String key) {
        this.siteminderPasswordHeaderKey = key;
    }

    /**
     * Sets the Siteminder username header key.
     *
     * @param key The Siteminder username header key.
     */
    public void setSiteminderUsernameHeaderKey(final String key) {
        this.siteminderUsernameHeaderKey = key;
    }
}
