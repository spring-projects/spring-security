package net.sf.acegisecurity.ui.x509;

import net.sf.acegisecurity.ui.AbstractProcessingFilter;
import net.sf.acegisecurity.ui.WebAuthenticationDetails;
import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.AuthenticationException;
import net.sf.acegisecurity.context.ContextHolder;
import net.sf.acegisecurity.context.security.SecureContext;
import net.sf.acegisecurity.providers.x509.X509AuthenticationToken;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.cert.X509Certificate;

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
public class X509ProcessingFilter extends AbstractProcessingFilter {

    public String getDefaultFilterProcessesUrl() {
        return "/*";
    }

    /**
     * X.509 authentication doesn't have a specific login URL, so the default implementation
     * using <code>endsWith</code> isn't adequate.
     *
     */
    protected boolean requiresAuthentication(HttpServletRequest request,
        HttpServletResponse response) {
        return true; // for the time being. Should probably do a pattern match on the URL
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
        } else {
            logger.warn("No client certificate found in Request.");
        }
        // TODO: warning is probably superfluous, as it may get called when a non-protected URL is used and no certificate is present.

        X509AuthenticationToken authRequest = new X509AuthenticationToken(clientCertificate);

        // authRequest.setDetails(new WebAuthenticationDetails(request));

        return this.getAuthenticationManager().authenticate(authRequest);
    }
}
