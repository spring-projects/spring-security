/**
 *
 */
package org.acegisecurity.ui.ntlm.ldap.authenticator;

import java.util.Iterator;

import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.Authentication;
import org.acegisecurity.ldap.InitialDirContextFactory;
import org.acegisecurity.ldap.SpringSecurityLdapTemplate;
import org.acegisecurity.providers.ldap.authenticator.BindAuthenticator;
import org.acegisecurity.ui.ntlm.NtlmUsernamePasswordAuthenticationToken;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.NameNotFoundException;

/**
 * Loads the UserDetails if authentication was already performed by NTLM (indicated by the type of authentication
 * token submitted). Otherwise falls back to the parent class behaviour, attempting to bind as the user.
 *
 * @author sylvain.mougenot
 *
 */
public class NtlmAwareLdapAuthenticatorImpl extends BindAuthenticator {
    //~ Static fields/initializers =====================================================================================

    private static final Log logger = LogFactory.getLog(NtlmAwareLdapAuthenticatorImpl.class);


    //~ Constructors ===================================================================================================

	public NtlmAwareLdapAuthenticatorImpl(InitialDirContextFactory initialDirContextFactory) {
		super(initialDirContextFactory);
	}

    //~ Methods ========================================================================================================

    /**
     * Loads the user context information without binding.
	 */
	protected DirContextOperations loadUser(String aUserDn, String aUserName) {
		SpringSecurityLdapTemplate template = new SpringSecurityLdapTemplate(getInitialDirContextFactory());

		try {
			DirContextOperations user =  template.retrieveEntry(aUserDn, getUserAttributes());

			return user;
		} catch (NameNotFoundException e) {
			// This will be thrown if an invalid user name is used and the method may
			// be called multiple times to try different names, so we trap the exception.
			if (logger.isDebugEnabled()) {
				logger.debug("Failed to load user " + aUserDn + ": " + e.getMessage(), e);
			}
		}
		return null;
	}

	/**
	 * If the supplied <tt>Authentication</tt> object is of type <tt>NtlmUsernamePasswordAuthenticationToken</tt>,
     * the information stored in the user's directory entry is loaded without attempting to authenticate them.
     * Otherwise the parent class is called to perform a bind operation to authenticate the user.
	 */
	public DirContextOperations authenticate(Authentication authentication) {
        if (!(authentication instanceof NtlmUsernamePasswordAuthenticationToken)) {
            // Not NTLM authenticated, so call the base class to authenticate the user.
            return super.authenticate(authentication);
        }

        if (logger.isDebugEnabled()) {
			logger.debug("authenticate(NtlmUsernamePasswordAuthenticationToken) - start"); //$NON-NLS-1$
		}

		final String userName = authentication.getName();
		DirContextOperations user = null;

		// If DN patterns are configured, try authenticating with them directly
		Iterator myDns = getUserDns(userName).iterator();

		// tries them all until we found something
		while (myDns.hasNext() && (user == null)) {
			user = loadUser((String) myDns.next(), userName);
		}

		// Otherwise use the configured locator to find the user
		// and authenticate with the returned DN.
		if ((user == null) && (getUserSearch() != null)) {
			DirContextOperations userFromSearch = getUserSearch().searchForUser(userName);
			// lancer l'identificvation
			user = loadUser(userFromSearch.getDn().toString(), userName);
		}

		// Failed to locate the user in the LDAP directory
		if (user == null) {
			throw new BadCredentialsException(messages.getMessage("BindAuthenticator.badCredentials", "Bad credentials"));
		}

		if (logger.isDebugEnabled()) {
			logger.debug("authenticate(NtlmUsernamePasswordAuthenticationToken) - end"); //$NON-NLS-1$
		}
		return user;
	}
}
