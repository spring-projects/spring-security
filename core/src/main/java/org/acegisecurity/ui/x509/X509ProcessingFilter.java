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
import net.sf.acegisecurity.providers.x509.X509AuthenticationProvider;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.*;
import java.security.cert.X509Certificate;
import java.io.IOException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;

/**
 * Processes the X.509 certificate submitted by a client - typically
 * when HTTPS is used with client-authentiction enabled.
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

    private AuthenticationManager authenticationManager;


    public void setAuthenticationManager(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    public void afterPropertiesSet() throws Exception {
        if(authenticationManager == null)
            throw new IllegalArgumentException("An AuthenticationManager must be set");
    }

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain) throws IOException, ServletException {
        if (!(request instanceof HttpServletRequest)) {
            throw new ServletException("Can only process HttpServletRequest");
        }

        if (!(response instanceof HttpServletResponse)) {
            throw new ServletException("Can only process HttpServletResponse");
        }


        SecureContext ctx = SecureContextUtils.getSecureContext();

        logger.debug("Checking secure context: " + ctx);
        if(ctx.getAuthentication() == null) {
            attemptAuthentication((HttpServletRequest)request);

        }

        filterChain.doFilter(request, response);
    }

    /**
     *
     * @param request the request containing the client certificate
     * @return
     * @throws AuthenticationException if the authentication manager rejects the certificate for some reason.
     */
    public Authentication attemptAuthentication(HttpServletRequest request) throws AuthenticationException {
        X509Certificate[] certs = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");

        X509Certificate clientCertificate = null;

        if(certs != null && certs.length > 0) {
            clientCertificate = certs[0];
            logger.debug("Authenticating with certificate " + clientCertificate);
        } else {
            logger.warn("No client certificate found in Request.");
        }
        // TODO: warning is probably superfluous, as it may get called when a non-protected URL is used and no certificate is present.

        X509AuthenticationToken authRequest = new X509AuthenticationToken(clientCertificate);

        // authRequest.setDetails(new WebAuthenticationDetails(request));

        return authenticationManager.authenticate(authRequest);
    }

    public void init(FilterConfig filterConfig) throws ServletException { }


    public void destroy() { }


}
