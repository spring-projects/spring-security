/**
 * 
 */
package org.acegisecurity.ui.ntlm.ldap.authenticator;

import org.acegisecurity.providers.ldap.LdapAuthenticator;
import org.acegisecurity.ui.ntlm.NtlmUsernamePasswordAuthenticationToken;
import org.springframework.ldap.core.DirContextOperations;

/**
 * Authenticator compliant with NTLM part done previously (for authentication).
 * 
 * @author sylvain.mougenot
 *
 */
public interface NtlmAwareLdapAuthenticator extends LdapAuthenticator {
    /**
     * Authentication was done previously by NTLM.
     * Obtains additional user informations from the directory.
     *
     * @param aUserToken Ntlm issued authentication Token
     * @return the details of the successfully authenticated user.
     */
    DirContextOperations authenticate(NtlmUsernamePasswordAuthenticationToken aUserToken);
}
