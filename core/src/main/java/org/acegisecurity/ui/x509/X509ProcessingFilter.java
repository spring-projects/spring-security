package net.sf.acegisecurity.ui.x509;

import net.sf.acegisecurity.ui.AbstractProcessingFilter;
import net.sf.acegisecurity.ui.WebAuthenticationDetails;
import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.AuthenticationException;
import net.sf.acegisecurity.AuthenticationManager;
import net.sf.acegisecurity.context.ContextHolder;
import net.sf.acegisecurity.context.security.SecureContext;
import net.sf.acegisecurity.context.security.SecureContextUtils;
import net.sf.acegisecurity.providers.x509.X509AuthenticationToken;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.*;
import java.security.cert.X509Certificate;
import java.io.IOException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;

/**
 * Processes the X.509 certificate submitted by a client browser
 * when HTTPS is used with client-authentication enabled.
 * <p>
 * An {@link X509AuthenticationToken} is created with the certificate
 * as the credentials.
 * </p>
 * <p>
 * The configured authentication manager is expected to supply a
 * provider which can handle this token (usually an instance of
 * {@link net.sf.acegisecurity.providers.x509.X509AuthenticationProvider}).
 * </p>
 *
 * <p>
 * <b>Do not use this class directly.</b> Instead configure
 * <code>web.xml</code> to use the {@link
 * net.sf.acegisecurity.util.FilterToBeanProxy}.
 * </p>
 *
 * @author Luke Taylor
 */
public class X509ProcessingFilter implements Filter, InitializingBean {
    //~ Static fields/initializers =============================================

    private static final Log logger = LogFactory.getLog(X509ProcessingFilter.class);

    //~ Instance fields ========================================================

    private AuthenticationManager authenticationManager;

    //~ Methods ================================================================

    public void setAuthenticationManager(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    public void afterPropertiesSet() throws Exception {
        if(authenticationManager == null)
            throw new IllegalArgumentException("An AuthenticationManager must be set");
    }

    /**
     * This method first checks for an existing, non-null authentication in the
     * secure context. If one is found it does nothing.
     * <p>
     * If no authentication object exists, it attempts to obtain the client
     * authentication certificate from the request. If there is no certificate
     * present then authentication is skipped. Otherwise a new authentication
     * request containing the certificate will be passed to the configured
     * {@link AuthenticationManager}.
     * </p>
     * <p>
     * If authentication is successful the returned token will be stored in
     * the secure context. Otherwise it will be set to null.
     * In either case, the request proceeds through the filter chain.
     * </p>
     */
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain) throws IOException, ServletException {
        if (!(request instanceof HttpServletRequest)) {
            throw new ServletException("Can only process HttpServletRequest");
        }

        if (!(response instanceof HttpServletResponse)) {
            throw new ServletException("Can only process HttpServletResponse");
        }

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        SecureContext ctx = SecureContextUtils.getSecureContext();

        logger.debug("Checking secure context token: " + ctx.getAuthentication());

        if(ctx.getAuthentication() == null) {

            Authentication authResult = null;
            X509Certificate clientCertificate = extractClientCertificate(httpRequest);

            try {
                X509AuthenticationToken authRequest = new X509AuthenticationToken(clientCertificate);
                // authRequest.setDetails(new WebAuthenticationDetails(request));

                authResult = authenticationManager.authenticate(authRequest);
                successfulAuthentication(httpRequest, httpResponse, authResult);
            } catch (AuthenticationException failed) {
                unsuccessfulAuthentication(httpRequest, httpResponse, failed);
            }
        }
        filterChain.doFilter(request, response);
    }

    private X509Certificate extractClientCertificate(HttpServletRequest request) {
        X509Certificate[] certs = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");

        if(certs != null && certs.length > 0) {
            return certs[0];
        }

        if(logger.isDebugEnabled())
            logger.debug("No client certificate found in request, authentication will fail.");

        return null;
    }

    /**
     * Puts the <code>Authentication</code> instance returned by the authentication manager into
     * the secure context.
     */
    protected void successfulAuthentication(HttpServletRequest request,
        HttpServletResponse response, Authentication authResult)
        throws IOException {

        if (logger.isDebugEnabled()) {
            logger.debug("Authentication success: " + authResult);
        }
        SecureContext sc = SecureContextUtils.getSecureContext();
        sc.setAuthentication(authResult);
    }

    /**
     * Ensures the authentication object in the secure context is set to null when authentication fails.
     *
     */
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) {
        SecureContext sc = SecureContextUtils.getSecureContext();

        sc.setAuthentication(null);
        ContextHolder.setContext(sc);

        if (logger.isDebugEnabled()) {
            logger.debug("Updated ContextHolder to contain null Authentication");
        }

        request.getSession().setAttribute(AbstractProcessingFilter.ACEGI_SECURITY_LAST_EXCEPTION_KEY, failed);
    }


    public void init(FilterConfig filterConfig) throws ServletException { }


    public void destroy() { }


}
