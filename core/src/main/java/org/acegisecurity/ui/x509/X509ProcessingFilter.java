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

package org.acegisecurity.ui.x509;

import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.AuthenticationManager;

import org.acegisecurity.context.SecurityContextHolder;

import org.acegisecurity.event.authentication.InteractiveAuthenticationSuccessEvent;

import org.acegisecurity.providers.x509.X509AuthenticationToken;

import org.acegisecurity.ui.AbstractProcessingFilter;
import org.acegisecurity.ui.AuthenticationDetailsSource;
import org.acegisecurity.ui.AuthenticationDetailsSourceImpl;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.factory.InitializingBean;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;

import org.springframework.util.Assert;

import java.io.IOException;

import java.security.cert.X509Certificate;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


/**
 * Processes the X.509 certificate submitted by a client browser when HTTPS is
 * used with client-authentication enabled.
 * 
 * <p>
 * An {@link X509AuthenticationToken} is created with the certificate as the
 * credentials.
 * </p>
 * 
 * <p>
 * The configured authentication manager is expected to supply a provider which
 * can handle this token (usually an instance of {@link
 * org.acegisecurity.providers.x509.X509AuthenticationProvider}).
 * </p>
 * 
 * <p>
 * If authentication is successful, an {@link
 * org.acegisecurity.event.authentication.InteractiveAuthenticationSuccessEvent}
 * will be published to the application context. No events will be published
 * if authentication was unsuccessful, because this would generally be
 * recorded via an <code>AuthenticationManager</code>-specific application
 * event.
 * </p>
 * 
 * <p>
 * <b>Do not use this class directly.</b> Instead configure
 * <code>web.xml</code> to use the {@link
 * org.acegisecurity.util.FilterToBeanProxy}.
 * </p>
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class X509ProcessingFilter implements Filter, InitializingBean,
    ApplicationEventPublisherAware {
    //~ Static fields/initializers =============================================

    private static final Log logger = LogFactory.getLog(X509ProcessingFilter.class);

    //~ Instance fields ========================================================

    private ApplicationEventPublisher eventPublisher;
    private AuthenticationDetailsSource authenticationDetailsSource = new AuthenticationDetailsSourceImpl();
    private AuthenticationManager authenticationManager;

    //~ Methods ================================================================

    public void afterPropertiesSet() throws Exception {
        Assert.notNull(authenticationManager,
            "An AuthenticationManager must be set");
    }

    public void destroy() {}

    /**
     * This method first checks for an existing, non-null authentication in the
     * secure context. If one is found it does nothing.
     * 
     * <p>
     * If no authentication object exists, it attempts to obtain the client
     * authentication certificate from the request. If there is no certificate
     * present then authentication is skipped. Otherwise a new authentication
     * request containing the certificate will be passed to the configured
     * {@link AuthenticationManager}.
     * </p>
     * 
     * <p>
     * If authentication is successful the returned token will be stored in the
     * secure context. Otherwise it will be set to null. In either case, the
     * request proceeds through the filter chain.
     * </p>
     *
     * @param request DOCUMENT ME!
     * @param response DOCUMENT ME!
     * @param filterChain DOCUMENT ME!
     *
     * @throws IOException DOCUMENT ME!
     * @throws ServletException DOCUMENT ME!
     */
    public void doFilter(ServletRequest request, ServletResponse response,
        FilterChain filterChain) throws IOException, ServletException {
        if (!(request instanceof HttpServletRequest)) {
            throw new ServletException("Can only process HttpServletRequest");
        }

        if (!(response instanceof HttpServletResponse)) {
            throw new ServletException("Can only process HttpServletResponse");
        }

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        if (logger.isDebugEnabled()) {
            logger.debug("Checking secure context token: "
                + SecurityContextHolder.getContext().getAuthentication());
        }

        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            Authentication authResult = null;
            X509Certificate clientCertificate = extractClientCertificate(httpRequest);

            try {
                X509AuthenticationToken authRequest = new X509AuthenticationToken(clientCertificate);

                authRequest.setDetails(authenticationDetailsSource.buildDetails(
                        (HttpServletRequest) request));
                authResult = authenticationManager.authenticate(authRequest);
                successfulAuthentication(httpRequest, httpResponse, authResult);
            } catch (AuthenticationException failed) {
                unsuccessfulAuthentication(httpRequest, httpResponse, failed);
            }
        }

        filterChain.doFilter(request, response);
    }

    private X509Certificate extractClientCertificate(HttpServletRequest request) {
        X509Certificate[] certs = (X509Certificate[]) request.getAttribute(
                "javax.servlet.request.X509Certificate");

        if ((certs != null) && (certs.length > 0)) {
            return certs[0];
        }

        if (logger.isDebugEnabled()) {
            logger.debug("No client certificate found in request.");
        }

        return null;
    }

    public void init(FilterConfig ignored) throws ServletException {}

    public void setApplicationEventPublisher(ApplicationEventPublisher context) {
        this.eventPublisher = context;
    }

    public void setAuthenticationDetailsSource(
        AuthenticationDetailsSource authenticationDetailsSource) {
        Assert.notNull(authenticationDetailsSource,
            "AuthenticationDetailsSource required");
        this.authenticationDetailsSource = authenticationDetailsSource;
    }

    public void setAuthenticationManager(
        AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    /**
     * Puts the <code>Authentication</code> instance returned by the
     * authentication manager into the secure context.
     *
     * @param request DOCUMENT ME!
     * @param response DOCUMENT ME!
     * @param authResult DOCUMENT ME!
     *
     * @throws IOException DOCUMENT ME!
     */
    protected void successfulAuthentication(HttpServletRequest request,
        HttpServletResponse response, Authentication authResult)
        throws IOException {
        if (logger.isDebugEnabled()) {
            logger.debug("Authentication success: " + authResult);
        }

        SecurityContextHolder.getContext().setAuthentication(authResult);

        // Fire event
        if (this.eventPublisher != null) {
            eventPublisher.publishEvent(new InteractiveAuthenticationSuccessEvent(
                    authResult, this.getClass()));
        }
    }

    /**
     * Ensures the authentication object in the secure context is set to null
     * when authentication fails.
     *
     * @param request DOCUMENT ME!
     * @param response DOCUMENT ME!
     * @param failed DOCUMENT ME!
     */
    protected void unsuccessfulAuthentication(HttpServletRequest request,
        HttpServletResponse response, AuthenticationException failed) {
        SecurityContextHolder.getContext().setAuthentication(null);

        if (logger.isDebugEnabled()) {
            logger.debug(
                "Updated SecurityContextHolder to contain null Authentication");
        }

        request.getSession()
               .setAttribute(AbstractProcessingFilter.ACEGI_SECURITY_LAST_EXCEPTION_KEY,
            failed);
    }
}
