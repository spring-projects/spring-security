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
import net.sf.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import net.sf.acegisecurity.ui.AbstractProcessingFilter;

import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;


/**
 * Processes an authentication form.
 * 
 * <p>
 * Login forms must present two parameters to this filter: a username and
 * password. The parameter names to use are contained in the static fields
 * {@link #ACEGI_SECURITY_FORM_USERNAME_KEY} and {@link
 * #ACEGI_SECURITY_FORM_PASSWORD_KEY}.
 * </p>
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
public class AuthenticationProcessingFilter extends AbstractProcessingFilter {
    //~ Static fields/initializers =============================================

    public static final String ACEGI_SECURITY_FORM_USERNAME_KEY = "j_username";
    public static final String ACEGI_SECURITY_FORM_PASSWORD_KEY = "j_password";

    //~ Methods ================================================================

    /**
     * This filter by default responds to <code>/j_acegi_security_check</code>.
     *
     * @return the default
     */
    public String getDefaultFilterProcessesUrl() {
        return "/j_acegi_security_check";
    }

    public Authentication attemptAuthentication(HttpServletRequest request)
        throws AuthenticationException {
        String username = request.getParameter(ACEGI_SECURITY_FORM_USERNAME_KEY);
        String password = request.getParameter(ACEGI_SECURITY_FORM_PASSWORD_KEY);

        if (username == null) {
            username = "";
        }

        if (password == null) {
            password = "";
        }

        UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(username,
                password);

        // Allow subclasses to set the "details" property
        setDetails(request, authRequest);

        return this.getAuthenticationManager().authenticate(authRequest);
    }

    public void init(FilterConfig filterConfig) throws ServletException {}

    /**
     * Provided so that subclasses may configure what is put into the
     * authentication request's details property. Default implementation
     * simply sets the IP address of the servlet request.
     *
     * @param request that an authentication request is being created for
     * @param authRequest the authentication request object that should have
     *        its details set
     */
    protected void setDetails(HttpServletRequest request,
        UsernamePasswordAuthenticationToken authRequest) {
        authRequest.setDetails(request.getRemoteAddr());
    }
}
