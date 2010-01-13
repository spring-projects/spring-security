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

package org.springframework.security.web.authentication;


import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.util.TextEscapeUtils;
import org.springframework.util.Assert;


/**
 * Processes an authentication form submission. Called {@code AuthenticationProcessingFilter} prior to Spring Security
 * 3.0.
 * <p>
 * Login forms must present two parameters to this filter: a username and
 * password. The default parameter names to use are contained in the
 * static fields {@link #SPRING_SECURITY_FORM_USERNAME_KEY} and {@link #SPRING_SECURITY_FORM_PASSWORD_KEY}.
 * The parameter names can also be changed by setting the {@literal usernameParameter} and {@literal passwordParameter}
 * properties.
 * <p>
 * This filter by default responds to the URL {@literal /j_spring_security_check}.
 *
 * @author Ben Alex
 * @author Colin Sampaleanu
 * @author Luke Taylor
 * @since 3.0
 */
public class UsernamePasswordAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
    //~ Static fields/initializers =====================================================================================

    public static final String SPRING_SECURITY_FORM_USERNAME_KEY = "j_username";
    public static final String SPRING_SECURITY_FORM_PASSWORD_KEY = "j_password";
    public static final String SPRING_SECURITY_LAST_USERNAME_KEY = "SPRING_SECURITY_LAST_USERNAME";

    private String usernameParameter = SPRING_SECURITY_FORM_USERNAME_KEY;
    private String passwordParameter = SPRING_SECURITY_FORM_PASSWORD_KEY;
    private boolean postOnly = true;

    //~ Constructors ===================================================================================================

    public UsernamePasswordAuthenticationFilter() {
        super("/j_spring_security_check");
    }

    //~ Methods ========================================================================================================

    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        if (postOnly && !request.getMethod().equals("POST")) {
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        }

        String username = obtainUsername(request);
        String password = obtainPassword(request);

        if (username == null) {
            username = "";
        }

        if (password == null) {
            password = "";
        }

        username = username.trim();

        UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(username, password);

        // Place the last username attempted into HttpSession for views
        HttpSession session = request.getSession(false);

        if (session != null || getAllowSessionCreation()) {
            request.getSession().setAttribute(SPRING_SECURITY_LAST_USERNAME_KEY, TextEscapeUtils.escapeEntities(username));
        }

        // Allow subclasses to set the "details" property
        setDetails(request, authRequest);

        return this.getAuthenticationManager().authenticate(authRequest);
    }

    /**
     * Enables subclasses to override the composition of the password, such as by including additional values
     * and a separator.<p>This might be used for example if a postcode/zipcode was required in addition to the
     * password. A delimiter such as a pipe (|) should be used to separate the password and extended value(s). The
     * <code>AuthenticationDao</code> will need to generate the expected password in a corresponding manner.</p>
     *
     * @param request so that request attributes can be retrieved
     *
     * @return the password that will be presented in the <code>Authentication</code> request token to the
     *         <code>AuthenticationManager</code>
     */
    protected String obtainPassword(HttpServletRequest request) {
        return request.getParameter(passwordParameter);
    }

    /**
     * Enables subclasses to override the composition of the username, such as by including additional values
     * and a separator.
     *
     * @param request so that request attributes can be retrieved
     *
     * @return the username that will be presented in the <code>Authentication</code> request token to the
     *         <code>AuthenticationManager</code>
     */
    protected String obtainUsername(HttpServletRequest request) {
        return request.getParameter(usernameParameter);
    }

    /**
     * Provided so that subclasses may configure what is put into the authentication request's details
     * property.
     *
     * @param request that an authentication request is being created for
     * @param authRequest the authentication request object that should have its details set
     */
    protected void setDetails(HttpServletRequest request, UsernamePasswordAuthenticationToken authRequest) {
        authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
    }

    /**
     * Sets the parameter name which will be used to obtain the username from the login request.
     *
     * @param usernameParameter the parameter name. Defaults to "j_username".
     */
    public void setUsernameParameter(String usernameParameter) {
        Assert.hasText(usernameParameter, "Username parameter must not be empty or null");
        this.usernameParameter = usernameParameter;
    }

    /**
     * Sets the parameter name which will be used to obtain the password from the login request..
     *
     * @param passwordParameter the parameter name. Defaults to "j_password".
     */
    public void setPasswordParameter(String passwordParameter) {
        Assert.hasText(passwordParameter, "Password parameter must not be empty or null");
        this.passwordParameter = passwordParameter;
    }

    /**
     * Defines whether only HTTP POST requests will be allowed by this filter.
     * If set to true, and an authentication request is received which is not a POST request, an exception will
     * be raised immediately and authentication will not be attempted. The <tt>unsuccessfulAuthentication()</tt> method
     * will be called as if handling a failed authentication.
     * <p>
     * Defaults to <tt>true</tt> but may be overridden by subclasses.
     */
    public void setPostOnly(boolean postOnly) {
        this.postOnly = postOnly;
    }

    public final String getUsernameParameter() {
        return usernameParameter;
    }

    public final String getPasswordParameter() {
        return passwordParameter;
    }
}
