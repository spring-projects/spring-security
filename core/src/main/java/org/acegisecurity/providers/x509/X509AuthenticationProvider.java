package net.sf.acegisecurity.providers.x509;

import net.sf.acegisecurity.providers.AuthenticationProvider;
import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.AuthenticationException;
import net.sf.acegisecurity.UserDetails;
import net.sf.acegisecurity.BadCredentialsException;
import org.springframework.beans.factory.InitializingBean;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.security.cert.X509Certificate;

/**
 * Processes an X.509 authentication request.
 * <p>
 * The request will typically originate from
 * {@link net.sf.acegisecurity.ui.x509.X509ProcessingFilter}).
 *
 * @author Luke Taylor
 */
public class X509AuthenticationProvider implements AuthenticationProvider,
    InitializingBean {
    //~ Static fields/initializers =============================================
    
    private static final Log logger = LogFactory.getLog(X509AuthenticationProvider.class);

    //~ Instance fields ========================================================

    private X509AuthoritiesPopulator x509AuthoritiesPopulator;

    //~ Methods ================================================================

    public void setX509AuthoritiesPopulator(X509AuthoritiesPopulator x509AuthoritiesPopulator) {
        this.x509AuthoritiesPopulator = x509AuthoritiesPopulator;
    }

    public void afterPropertiesSet() throws Exception {
        if(x509AuthoritiesPopulator == null) {
            throw new IllegalArgumentException("An X509AuthoritiesPopulator must be set");
        }
    }

    /**
     * If the supplied authentication token contains a certificate then this will be passed
     * to the configured {@link X509AuthoritiesPopulator}
     * to obtain the user details and authorities for the user identified by the certificate.
     * <p>
     * If no certificate is present (for example, if the filter is applied to an HttpRequest for which
     * client authentication hasn't been configured in the container) then a BadCredentialsException will be raised.
     * </p>
     *
     * @param authentication the authentication request.
     * @return an X509AuthenticationToken containing the authorities of the principal represented by the
     * certificate.
     * @throws AuthenticationException if the {@link X509AuthoritiesPopulator} rejects the certficate.
     * @throws BadCredentialsException if no certificate was presented in the authentication request.
     */
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (!supports(authentication.getClass())) {
            return null;
        }

        if(logger.isDebugEnabled())
            logger.debug("X509 authentication request: " + authentication);

        X509Certificate clientCertificate = (X509Certificate)authentication.getCredentials();

        if(clientCertificate == null) {
            //logger.debug("Certificate is null. Returning null Authentication.");
            throw new BadCredentialsException("Certificate is null.");
        }

        // TODO: Cache

        logger.debug("Authenticating with certificate " + clientCertificate);

        // Lookup user details for the given certificate
        UserDetails userDetails = x509AuthoritiesPopulator.getUserDetails(clientCertificate);

        return new X509AuthenticationToken(userDetails, clientCertificate, userDetails.getAuthorities());
    }

    public boolean supports(Class authentication) {
        return X509AuthenticationToken.class.isAssignableFrom(authentication);
    }

}
