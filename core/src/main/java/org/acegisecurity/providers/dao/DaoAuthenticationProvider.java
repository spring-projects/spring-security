/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
 */

package net.sf.acegisecurity.providers.dao;

import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.AuthenticationException;
import net.sf.acegisecurity.AuthenticationServiceException;
import net.sf.acegisecurity.BadCredentialsException;
import net.sf.acegisecurity.DisabledException;
import net.sf.acegisecurity.providers.AuthenticationProvider;
import net.sf.acegisecurity.providers.UsernamePasswordAuthenticationToken;

import org.springframework.beans.factory.InitializingBean;

import org.springframework.dao.DataAccessException;


/**
 * An {@link AuthenticationProvider} implementation that retrieves user details
 * from an {@link AuthenticationDao}.
 * 
 * <p>
 * This <code>AuthenticationProvider</code> is capable of validating  {@link
 * UsernamePasswordAuthenticationToken} requests contain the correct username,
 * password and the user is not disabled.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class DaoAuthenticationProvider implements AuthenticationProvider,
                                                  InitializingBean {
    //~ Instance fields ========================================================

    private AuthenticationDao authenticationDao;
    private boolean ignorePasswordCase = false;
    private boolean ignoreUsernameCase = true;

    //~ Methods ================================================================

    public void setAuthenticationDao(AuthenticationDao authenticationDao) {
        this.authenticationDao = authenticationDao;
    }

    public AuthenticationDao getAuthenticationDao() {
        return authenticationDao;
    }

    /**
     * Indicates whether the password comparison is case sensitive. Defaults to
     * <code>false</code>, meaning an exact case match is required.
     *
     * @param ignorePasswordCase set to <code>true</code> for less stringent
     *        comparison
     */
    public void setIgnorePasswordCase(boolean ignorePasswordCase) {
        this.ignorePasswordCase = ignorePasswordCase;
    }

    public boolean isIgnorePasswordCase() {
        return ignorePasswordCase;
    }

    /**
     * Indicates whether the username search is case sensitive. Default to
     * <code>true</code>, meaning an exact case match is not  required.
     *
     * @param ignoreUsernameCase set to <code>false</code> for more stringent
     *        comparison
     */
    public void setIgnoreUsernameCase(boolean ignoreUsernameCase) {
        this.ignoreUsernameCase = ignoreUsernameCase;
    }

    public boolean isIgnoreUsernameCase() {
        return ignoreUsernameCase;
    }

    public void afterPropertiesSet() throws Exception {
        if (this.authenticationDao == null) {
            throw new IllegalArgumentException("An Authentication DAO must be set");
        }
    }

    public Authentication authenticate(Authentication authentication)
                                throws AuthenticationException {
        User user = null;

        try {
            user = this.authenticationDao.loadUserByUsername(authentication.getPrincipal()
                                                                           .toString());
        } catch (UsernameNotFoundException notFound) {
            throw new BadCredentialsException("Bad credentials presented");
        } catch (DataAccessException repositoryProblem) {
            throw new AuthenticationServiceException(repositoryProblem
                                                     .getMessage());
        }

        if (!user.isEnabled()) {
            throw new DisabledException("User is disabled");
        }

        if (!user.getPassword().equals(authentication.getCredentials().toString())) {
            throw new BadCredentialsException("Bad credentials presented");
        }

        return new UsernamePasswordAuthenticationToken(user.getUsername(),
                                                       user.getPassword(),
                                                       user.getAuthorities());
    }

    public boolean supports(Class authentication) {
        if (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication)) {
            return true;
        } else {
            return false;
        }
    }
}
