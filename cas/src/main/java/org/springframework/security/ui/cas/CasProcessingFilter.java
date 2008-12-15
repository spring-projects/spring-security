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

package org.springframework.security.ui.cas;

import java.io.IOException;

import org.jasig.cas.client.proxy.ProxyGrantingTicketStorage;
import org.jasig.cas.client.util.CommonUtils;
import org.jasig.cas.client.validation.TicketValidator;
import org.springframework.security.Authentication;
import org.springframework.security.AuthenticationException;

import org.springframework.security.providers.UsernamePasswordAuthenticationToken;

import org.springframework.security.ui.AbstractProcessingFilter;
import org.springframework.security.ui.FilterChainOrder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


/**
 * Processes a CAS service ticket.
 * <p>
 * A service ticket consists of an opaque ticket string. It arrives at this filter by the user's browser successfully
 * authenticating using CAS, and then receiving a HTTP redirect to a <code>service</code>. The opaque ticket string is
 * presented in the <code>ticket</code> request parameter. This filter monitors the <code>service</code> URL so it can
 * receive the service ticket and process it. The CAS server knows which <code>service</code> URL to use via the
 * {@link ServiceProperties#getService()} method.
 * <p>
 * Processing the service ticket involves creating a <code>UsernamePasswordAuthenticationToken</code> which
 * uses {@link #CAS_STATEFUL_IDENTIFIER} for the <code>principal</code> and the opaque ticket string as the
 * <code>credentials</code>.
 * <p>
 * The configured <code>AuthenticationManager</code> is expected to provide a provider that can recognise
 * <code>UsernamePasswordAuthenticationToken</code>s containing this special <code>principal</code> name, and process
 * them accordingly by validation with the CAS server.
 * <p>
 * By configuring a shared {@link ProxyGrantingTicketStorage} between the {@link TicketValidator} and the
 * CasProcessingFilter one can have the CasProcessingFilter handle the proxying requirements for CAS. In addition, the
 * URI endpoint for the proxying would also need to be configured (i.e. the part after protocol, hostname, and port).
 * <p>
 * By default this filter processes the URL <tt>/j_spring_cas_security_check</tt>.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class CasProcessingFilter extends AbstractProcessingFilter {
    //~ Static fields/initializers =====================================================================================

    /** Used to identify a CAS request for a stateful user agent, such as a web browser. */
    public static final String CAS_STATEFUL_IDENTIFIER = "_cas_stateful_";

    /**
     * Used to identify a CAS request for a stateless user agent, such as a remoting protocol client (e.g.
     * Hessian, Burlap, SOAP etc). Results in a more aggressive caching strategy being used, as the absence of a
     * <code>HttpSession</code> will result in a new authentication attempt on every request.
     */
    public static final String CAS_STATELESS_IDENTIFIER = "_cas_stateless_";

    /**
     * The last portion of the receptor url, i.e. /proxy/receptor
     */
    private String proxyReceptorUrl;

    /**
     * The backing storage to store ProxyGrantingTicket requests.
     */
    private ProxyGrantingTicketStorage proxyGrantingTicketStorage;

    //~ Constructors ===================================================================================================

    public CasProcessingFilter() {
        super("/j_spring_cas_security_check");
    }

    //~ Methods ========================================================================================================

    public Authentication attemptAuthentication(final HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        final String username = CAS_STATEFUL_IDENTIFIER;
        String password = request.getParameter("ticket");

        if (password == null) {
            password = "";
        }

        UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(username, password);

        authRequest.setDetails(authenticationDetailsSource.buildDetails(request));

        return this.getAuthenticationManager().authenticate(authRequest);
    }

    /**
     * Overridden to provide proxying capabilities.
     */
    protected boolean requiresAuthentication(final HttpServletRequest request, final HttpServletResponse response) {
        final String requestUri = request.getRequestURI();

        if (CommonUtils.isEmpty(this.proxyReceptorUrl) || !requestUri.endsWith(this.proxyReceptorUrl) || this.proxyGrantingTicketStorage == null) {
            return super.requiresAuthentication(request, response);
        }

        try {
            CommonUtils.readAndRespondToProxyReceptorRequest(request, response, this.proxyGrantingTicketStorage);
            return false;
        } catch (final IOException e) {
            return super.requiresAuthentication(request, response);
        }
    }

    public final void setProxyReceptorUrl(final String proxyReceptorUrl) {
        this.proxyReceptorUrl = proxyReceptorUrl;
    }

    public final void setProxyGrantingTicketStorage(
            final ProxyGrantingTicketStorage proxyGrantingTicketStorage) {
        this.proxyGrantingTicketStorage = proxyGrantingTicketStorage;
    }

    public int getOrder() {
        return FilterChainOrder.CAS_PROCESSING_FILTER;
    }
}
