package net.sf.acegisecurity.providers.x509;

import net.sf.acegisecurity.providers.AuthenticationProvider;
import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.AuthenticationException;
import net.sf.acegisecurity.UserDetails;
import org.springframework.beans.factory.InitializingBean;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.security.cert.X509Certificate;

/**
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
     *
     * @param authentication
     * @return
     * @throws AuthenticationException if the {@link X509AuthoritiesPopulator} rejects the certficate
     */
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (!supports(authentication.getClass())) {
            return null;
        }

        if(logger.isDebugEnabled())
            logger.debug("X509 authentication request: " + authentication);

        X509Certificate clientCertificate = (X509Certificate)authentication.getCredentials();

        // TODO: Cache


        // Lookup user details for the given certificate
        UserDetails userDetails = x509AuthoritiesPopulator.getUserDetails(clientCertificate);

        return new X509AuthenticationToken(userDetails, clientCertificate, userDetails.getAuthorities());
    }

    public boolean supports(Class authentication) {
        return X509AuthenticationToken.class.isAssignableFrom(authentication);
    }

}
