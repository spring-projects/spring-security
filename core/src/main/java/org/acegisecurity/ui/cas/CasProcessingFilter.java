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

package net.sf.acegisecurity.ui.cas;

import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.AuthenticationException;
import net.sf.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import net.sf.acegisecurity.ui.AbstractProcessingFilter;

import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;


/**
 * Processes a CAS service ticket.
 * 
 * <p>
 * A service ticket consists of an opaque ticket string. It arrives at this
 * filter by the user's browser successfully authenticating using CAS, and
 * then receiving a HTTP redirect to a <code>service</code>. The opal ticket
 * string is presented in the <code>ticket</code> request parameter. This
 * filter monitors the <code>service</code> URL so it can receive the service
 * ticket and process it. The CAS server knows which <code>service</code> URL
 * to use via the {@link ServiceProperties#getService()} method.
 * </p>
 * 
 * <P>
 * Processing the service ticket involves creating a
 * <code>UsernamePasswordAuthenticationToken</code> which uses {@link
 * #CAS_STATEFUL_IDENTIFIER} for the <code>principal</code> and the opaque
 * ticket string as the <code>credentials</code>.
 * </p>
 * 
 * <P>
 * The configured <code>AuthenticationManager</code> is expected to provide a
 * provider that can recognise
 * <code>UsernamePasswordAuthenticationToken</code>s containing this special
 * <code>principal</code> name, and process them accordingly by validation
 * with the CAS server.
 * </p>
 * 
 * <P>
 * <B>Do not use this class directly.</B> Instead configure
 * <code>web.xml</code> to use the {@link
 * net.sf.acegisecurity.util.FilterToBeanProxy}.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class CasProcessingFilter extends AbstractProcessingFilter {
    //~ Static fields/initializers =============================================

    /**
     * Used to identify a CAS request for a stateful user agent, such as a web
     * browser.
     */
    public static final String CAS_STATEFUL_IDENTIFIER = "_cas_stateful_";

    /**
     * Used to identify a CAS request for a stateless user agent, such as a
     * remoting protocol client (eg Hessian, Burlap, SOAP etc). Results in a
     * more aggressive caching strategy being used, as the absence of a
     * <code>HttpSession</code> will result in a new authentication attempt on
     * every request.
     */
    public static final String CAS_STATELESS_IDENTIFIER = "_cas_stateless_";

    //~ Methods ================================================================

    /**
     * This filter by default responds to
     * <code>/j_acegi_cas_security_check</code>.
     *
     * @return the default
     */
    public String getDefaultFilterProcessesUrl() {
        return "/j_acegi_cas_security_check";
    }

    public Authentication attemptAuthentication(HttpServletRequest request)
        throws AuthenticationException {
        String username = CAS_STATEFUL_IDENTIFIER;
        String password = request.getParameter("ticket");

        if (password == null) {
            password = "";
        }

        UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(username,
                password);
        authRequest.setDetails(request.getRemoteAddr());

        return this.getAuthenticationManager().authenticate(authRequest);
    }

    public void init(FilterConfig filterConfig) throws ServletException {}
}
