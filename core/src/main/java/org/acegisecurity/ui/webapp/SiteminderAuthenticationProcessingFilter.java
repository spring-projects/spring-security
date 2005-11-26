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

package org.acegisecurity.ui.webapp;

import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationException;

import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;

import org.acegisecurity.ui.WebAuthenticationDetails;

import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;


/**
 * Extends Acegi's AuthenticationProcessingFilter to pick up Netegrity
 * Siteminder's headers.
 * 
 * <P>
 * Also provides a backup form-based authentication and the ability set source
 * key names.
 * </p>
 * 
 * <P>
 * <B>Siteminder</B> must present two <B>headers</B> to this filter, a username
 * and password. You must set the header keys before this filter is used for
 * authentication, otherwise Siteminder checks will be skipped. If the
 * Siteminder check is unsuccessful (i.e. if the headers are not found), then
 * the form parameters will be checked (see next paragraph). This allows
 * applications to optionally function even when their Siteminder
 * infrastructure is unavailable, as is often the case during development.
 * </p>
 * 
 * <P>
 * <B>Login forms</B> must present two <B>parameters</B> to this filter: a
 * username and password. If not specified, the parameter names to use are
 * contained in the static fields {@link #ACEGI_SECURITY_FORM_USERNAME_KEY}
 * and {@link #ACEGI_SECURITY_FORM_PASSWORD_KEY}.
 * </p>
 * 
 * <P>
 * <B>Do not use this class directly.</B> Instead, configure
 * <code>web.xml</code> to use the {@link
 * org.acegisecurity.util.FilterToBeanProxy}.
 * </p>
 */
public class SiteminderAuthenticationProcessingFilter
    extends AuthenticationProcessingFilter {
    //~ Instance fields ========================================================

    /** Form password request key. */
    private String formPasswordParameterKey = null;

    /** Form username request key. */
    private String formUsernameParameterKey = null;

    /** Siteminder password header key. */
    private String siteminderPasswordHeaderKey = null;

    /** Siteminder username header key. */
    private String siteminderUsernameHeaderKey = null;

    //~ Constructors ===========================================================

    /**
     * Basic constructor.
     */
    public SiteminderAuthenticationProcessingFilter() {
        super();
    }

    //~ Methods ================================================================

    /**
     * @see org.acegisecurity.ui.AbstractProcessingFilter#attemptAuthentication(javax.servlet.http.HttpServletRequest)
     */
    public Authentication attemptAuthentication(HttpServletRequest request)
        throws AuthenticationException {
        String username = null;
        String password = null;

        // Check the Siteminder headers for authentication info
        if ((siteminderUsernameHeaderKey != null)
            && (siteminderUsernameHeaderKey.length() > 0)
            && (siteminderPasswordHeaderKey != null)
            && (siteminderPasswordHeaderKey.length() > 0)) {
            username = request.getHeader(siteminderUsernameHeaderKey);
            password = request.getHeader(siteminderPasswordHeaderKey);
        }

        // If the Siteminder authentication info wasn't available, then get it
        // from the form parameters
        if ((username == null) || (username.length() == 0)
            || (password == null) || (password.length() == 0)) {
            if (logger.isDebugEnabled()) {
                logger.debug(
                    "Siteminder headers not found for authentication, so trying to use form values");
            }

            if ((formUsernameParameterKey != null)
                && (formUsernameParameterKey.length() > 0)) {
                username = request.getParameter(formUsernameParameterKey);
            } else {
                username = request.getParameter(ACEGI_SECURITY_FORM_USERNAME_KEY);
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

        UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(username,
                password);

        // Allow subclasses to set the "details" property
        setDetails(request, authRequest);

        // Place the last username attempted into HttpSession for views
        request.getSession()
               .setAttribute(ACEGI_SECURITY_LAST_USERNAME_KEY, username);

        return this.getAuthenticationManager().authenticate(authRequest);
    }

    /**
     * This filter by default responds to <code>/j_acegi_security_check</code>.
     *
     * @return the default
     */
    public String getDefaultFilterProcessesUrl() {
        return "/j_acegi_security_check";
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
     * @see javax.servlet.Filter#init(javax.servlet.FilterConfig)
     */
    public void init(FilterConfig filterConfig) throws ServletException {}

    /**
     * Enables subclasses to override the composition of the password, such as
     * by including additional values and a separator.
     * 
     * <p>
     * This might be used for example if a postcode/zipcode was required in
     * addition to the password. A delimiter such as a pipe (|) should be used
     * to separate the password and extended value(s). The
     * <code>AuthenticationDao</code> will need to generate the expected
     * password in a corresponding manner.
     * </p>
     *
     * @param request so that request attributes can be retrieved
     *
     * @return the password that will be presented in the
     *         <code>Authentication</code> request token to the
     *         <code>AuthenticationManager</code>
     */
    protected String obtainPassword(HttpServletRequest request) {
        if ((formPasswordParameterKey != null)
            && (formPasswordParameterKey.length() > 0)) {
            return request.getParameter(formPasswordParameterKey);
        } else {
            return request.getParameter(ACEGI_SECURITY_FORM_PASSWORD_KEY);
        }
    }

    /**
     * Provided so that subclasses may configure what is put into the
     * authentication request's details property. The default implementation
     * simply constructs {@link WebAuthenticationDetails}.
     *
     * @param request that an authentication request is being created for
     * @param authRequest the authentication request object that should have
     *        its details set
     */
    protected void setDetails(HttpServletRequest request,
        UsernamePasswordAuthenticationToken authRequest) {
        authRequest.setDetails(new WebAuthenticationDetails(request));
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
