package net.sf.acegisecurity.providers.x509;

import net.sf.acegisecurity.UserDetails;
import net.sf.acegisecurity.AuthenticationException;

import java.security.cert.X509Certificate;

/**
 * Populates the <code>UserDetails</code> associated with the X.509
 * certificate presented by a client.
 * <p>
 * Although the certificate will already have been validated by the web container,
 * implementations may choose to perform additional application-specific checks on
 * the certificate content here. If an implementation chooses to reject the certificate,
 * it should throw a {@link net.sf.acegisecurity.BadCredentialsException}.
 * </p>
 *
 * @author Luke
 */
public interface X509AuthoritiesPopulator {
    /**
     * Obtains the granted authorities for the specified user.
     *
     * <p>
     * May throw any <code>AuthenticationException</code> or return
     * <code>null</code> if the authorities are unavailable.
     * </p>
     *
     * @param userCertificate the X.509 certificate supplied
     *
     * @return the details of the indicated user (at minimum the granted
     *         authorities and the username)
     *
     * @throws net.sf.acegisecurity.AuthenticationException if the user details are not available
     *  or the certificate isn't valid for the application's purpose.
     */
    public UserDetails getUserDetails(X509Certificate userCertificate)
        throws AuthenticationException;

}
