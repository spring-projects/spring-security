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

package org.acegisecurity.ui.webapp;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.context.HttpSessionContextIntegrationFilter;
import org.acegisecurity.context.SecurityContext;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Extends Acegi's AuthenticationProcessingFilter to pick up CA/Netegrity Siteminder headers.
 * 
 * <P>Also provides a backup form-based authentication and the ability set source key names.</p>
 * 
 * <P><B>Siteminder</B> must present two <B>headers</B> to this filter, a username and password. You must set the
 * header keys before this filter is used for authentication, otherwise Siteminder checks will be skipped. If the
 * Siteminder check is unsuccessful (i.e. if the headers are not found), then the form parameters will be checked (see
 * next paragraph). This allows applications to optionally function even when their Siteminder infrastructure is
 * unavailable, as is often the case during development.</p>
 * 
 * <P><B>Login forms</B> must present two <B>parameters</B> to this filter: a username and password. If not
 * specified, the parameter names to use are contained in the static fields {@link #ACEGI_SECURITY_FORM_USERNAME_KEY}
 * and {@link #ACEGI_SECURITY_FORM_PASSWORD_KEY}.</p>
 * 
 * <P><B>Do not use this class directly.</B> Instead, configure <code>web.xml</code> to use the {@link
 * org.acegisecurity.util.FilterToBeanProxy}.</p>
 * 
 * @author Scott McCrory
 * @version $Id$
 */
public class SiteminderAuthenticationProcessingFilter extends AuthenticationProcessingFilter {

    //~ Static fields/initializers =====================================================================================

    /** Log instance for debugging */
    private static final Log logger = LogFactory.getLog(SiteminderAuthenticationProcessingFilter.class);

    //~ Instance fields ================================================================================================

    /** Form username request key. */
    private String formUsernameParameterKey = null;

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
     * @see org.acegisecurity.ui.AbstractProcessingFilter#attemptAuthentication(javax.servlet.http.HttpServletRequest)
     */
    public Authentication attemptAuthentication(final HttpServletRequest request) throws AuthenticationException {

        String username = null;

        // Check the Siteminder header for identification info
        if ((siteminderUsernameHeaderKey != null) && (siteminderUsernameHeaderKey.length() > 0)) {
            username = request.getHeader(siteminderUsernameHeaderKey);
        }

        // If the Siteminder identification info wasn't available, then try to get it from the form
        if ((username == null) || (username.length() == 0)) {
            if (logger.isDebugEnabled()) {
                logger.debug("Siteminder headers not found for authentication, so trying to use form values");
            }

            if ((formUsernameParameterKey != null) && (formUsernameParameterKey.length() > 0)) {
                username = request.getParameter(formUsernameParameterKey);
            } else {
                username = request.getParameter(ACEGI_SECURITY_FORM_USERNAME_KEY);
            }

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

        // Pass in a null password value because it isn't relevant for Siteminder.
        // Of course the AuthenticationManager needs to not care!
        UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(username, null);

        // Allow subclasses to set the "details" property
        setDetails(request, authRequest);

        // Place the last username attempted into HttpSession for views
        request.getSession().setAttribute(ACEGI_SECURITY_LAST_USERNAME_KEY, username);

        return this.getAuthenticationManager().authenticate(authRequest);
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
     * Returns the Siteminder username header key.
     *
     * @return The Siteminder username header key.
     */
    public String getSiteminderUsernameHeaderKey() {
        return siteminderUsernameHeaderKey;
    }

    /**
     * Overridden method to always return a null (Siteminder doesn't pass on the password).
     *
     * @param request so that request attributes can be retrieved
     * @return the password that will be presented in the <code>Authentication</code> request token to the
     *         <code>AuthenticationManager</code> (null).
     */
    protected String obtainPassword(final HttpServletRequest request) {
        return null;
    }

    /**
     * Overridden to perform authentication not only on j_security_check, but also on requests for the default
     * target URL when the user isn't already authenticated.<p>Thank you Paul Garvey for providing a
     * straightforward solution (and code) for this!</p>
     *
     * @see org.acegisecurity.ui.AbstractProcessingFilter#requiresAuthentication(javax.servlet.http.HttpServletRequest,
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
        SecurityContext context = (SecurityContext) request.getSession().getAttribute(
                HttpSessionContextIntegrationFilter.ACEGI_SECURITY_CONTEXT_KEY);

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
     * Sets the form username parameter key.
     *
     * @param key The form username parameter key.
     */
    public void setFormUsernameParameterKey(final String key) {
        this.formUsernameParameterKey = key;
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
