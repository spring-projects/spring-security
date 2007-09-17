/**
 * 
 */
package org.acegisecurity.ui.ntlm.ldap.authenticator;

import org.acegisecurity.*;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.providers.ldap.LdapAuthenticationProvider;
import org.acegisecurity.providers.ldap.LdapAuthoritiesPopulator;
import org.acegisecurity.ui.ntlm.NtlmUsernamePasswordAuthenticationToken;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.ldap.LdapUserDetails;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.util.StringUtils;
import org.springframework.ldap.core.DirContextOperations;

/**
 * This provider implements specialized behaviour if the supplied {@link Authentication} object is
 * from NTLM. In other cases calls the parent implementation.
 * 
 * @author sylvain.mougenot
 * 
 */
public class NtlmAwareLdapAuthenticationProvider extends LdapAuthenticationProvider {
	private static final Log logger = LogFactory.getLog(NtlmAwareLdapAuthenticationProvider.class);

	/**
	 * NTLM aware authenticator
	 */
	private NtlmAwareLdapAuthenticator authenticator;

	/**
	 * @param authenticator
	 * @param authoritiesPopulator
	 */
	public NtlmAwareLdapAuthenticationProvider(NtlmAwareLdapAuthenticator authenticator,
			                                    LdapAuthoritiesPopulator authoritiesPopulator) {
		super(authenticator, authoritiesPopulator);
		this.authenticator = authenticator;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.acegisecurity.providers.ldap.LdapAuthenticationProvider#retrieveUser(java.lang.String,
	 *      org.acegisecurity.providers.UsernamePasswordAuthenticationToken)
	 */
	protected UserDetails retrieveUser(String username, UsernamePasswordAuthenticationToken authentication)
			throws AuthenticationException {
		final UserDetails myDetails;

		if (authentication instanceof NtlmUsernamePasswordAuthenticationToken) {
			if (logger.isDebugEnabled()) {
				logger.debug("Ntlm Token for Authentication"); //$NON-NLS-1$
			}

			// Only loads LDAP data
			myDetails = retrieveUser(username, (NtlmUsernamePasswordAuthenticationToken) authentication);
		} else {
			// calls parent implementation
			myDetails = super.retrieveUser(username, authentication);
		}

		return myDetails;
	}

	/**
	 * Authentication has already been done. We need a particular behviour
	 * because the parent check password consistency. But we do not have the
	 * password (even if the user is authenticated).
	 * 
	 * @see NtlmUsernamePasswordAuthenticationToken#DEFAULT_PASSWORD
	 * @param username
	 * @param authentication
	 * @return
	 * @throws AuthenticationException
	 */
	protected UserDetails retrieveUser(String username, NtlmUsernamePasswordAuthenticationToken authentication)
			throws AuthenticationException {
		// identifiant obligatoire
		if (!StringUtils.hasLength(username)) {
			throw new BadCredentialsException(messages.getMessage(
					"LdapAuthenticationProvider.emptyUsername",
					"Empty Username"));
		}

		// NB: password is just the default value

		if (logger.isDebugEnabled()) {
			logger.debug("Retrieving user " + username);
		}

		try {
			// Complies with our lack of password (can't bind)
			DirContextOperations ldapUser = authenticator.authenticate(authentication);

            GrantedAuthority[] extraAuthorities = getAuthoritiesPopulator().getGrantedAuthorities(ldapUser, username);

            return getUserDetailsContextMapper().mapUserFromContext(ldapUser, username, extraAuthorities);

		} catch (DataAccessException ldapAccessFailure) {
			throw new AuthenticationServiceException(ldapAccessFailure
					.getMessage(), ldapAccessFailure);
		}
	}
}
