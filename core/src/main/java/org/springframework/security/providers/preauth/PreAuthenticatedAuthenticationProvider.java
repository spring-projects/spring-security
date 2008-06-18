package org.springframework.security.providers.preauth;

import org.springframework.security.providers.AuthenticationProvider;
import org.springframework.security.Authentication;
import org.springframework.security.AuthenticationException;
import org.springframework.security.BadCredentialsException;
import org.springframework.security.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.userdetails.UserDetails;
import org.springframework.security.userdetails.UserDetailsChecker;
import org.springframework.security.userdetails.checker.AccountStatusUserDetailsChecker;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.Ordered;
import org.springframework.util.Assert;

/**
 * <p>
 * Processes a pre-authenticated authentication request. The request will
 * typically originate from a {@link org.springframework.security.ui.preauth.AbstractPreAuthenticatedProcessingFilter}
 * subclass.
 *
 * <p>
 * This authentication provider will not perform any checks on authentication
 * requests, as they should already be pre- authenticated. However, the
 * AuthenticationUserDetailsService implementation may still throw a UsernameNotFoundException, for example.
 *
 * @author Ruud Senden
 * @version $Id$
 * @since 2.0
 */
public class PreAuthenticatedAuthenticationProvider implements AuthenticationProvider, InitializingBean, Ordered {
    private static final Log logger = LogFactory.getLog(PreAuthenticatedAuthenticationProvider.class);

    private AuthenticationUserDetailsService preAuthenticatedUserDetailsService = null;
    private UserDetailsChecker userDetailsChecker = new AccountStatusUserDetailsChecker(); 
    private boolean throwExceptionWhenTokenRejected = false;

    private int order = -1; // default: same as non-ordered

    /**
     * Check whether all required properties have been set.
     */
    public void afterPropertiesSet() {
        Assert.notNull(preAuthenticatedUserDetailsService, "An AuthenticationUserDetailsService must be set");
    }

    /**
     * Authenticate the given PreAuthenticatedAuthenticationToken.
     * <p>
     * If the principal contained in the authentication object is null, the request will be ignored to allow other
     * providers to authenticate it.
     */
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (!supports(authentication.getClass())) {
            return null;
        }

        if (logger.isDebugEnabled()) {
            logger.debug("PreAuthenticated authentication request: " + authentication);
        }

        if (authentication.getPrincipal() == null) {
            logger.debug("No pre-authenticated principal found in request.");
            
            if (throwExceptionWhenTokenRejected) {
                throw new BadCredentialsException("No pre-authenticated principal found in request.");
            }
            return null;
        }

        if (authentication.getCredentials() == null) {
            logger.debug("No pre-authenticated credentials found in request.");

            if (throwExceptionWhenTokenRejected) {
                throw new BadCredentialsException("No pre-authenticated credentials found in request.");
            }            
            return null;
        }
        
        UserDetails ud = preAuthenticatedUserDetailsService.loadUserDetails(authentication);

        userDetailsChecker.check(ud);

        PreAuthenticatedAuthenticationToken result =
                new PreAuthenticatedAuthenticationToken(ud, authentication.getCredentials(), ud.getAuthorities());
        result.setDetails(authentication.getDetails());

        return result;
    }

    /**
     * Indicate that this provider only supports PreAuthenticatedAuthenticationToken (sub)classes.
     */
    public boolean supports(Class authentication) {
        return PreAuthenticatedAuthenticationToken.class.isAssignableFrom(authentication);
    }

    /**
     * Set the AuthenticatedUserDetailsServices to be used.
     *
     * @param aPreAuthenticatedUserDetailsService
     */
    public void setPreAuthenticatedUserDetailsService(AuthenticationUserDetailsService aPreAuthenticatedUserDetailsService) {
        this.preAuthenticatedUserDetailsService = aPreAuthenticatedUserDetailsService;
    }

    public int getOrder() {
        return order;
    }

    public void setOrder(int i) {
        order = i;
    }

    /** 
     * If true, causes the provider to throw a BadCredentialsException if the presented authentication 
     * request is invalid (contains a null principal or credentials). Otherwise it will just return 
     * null. Defaults to false.
     */    
    public void setThrowExceptionWhenTokenRejected(boolean throwExceptionWhenTokenRejected) {
        this.throwExceptionWhenTokenRejected = throwExceptionWhenTokenRejected;
    }

    /**
     * Sets the strategy which will be used to validate the loaded <tt>UserDetails</tt> object
     * for the user. Defaults to an {@link AccountStatusUserDetailsChecker}. 
     * @param userDetailsChecker
     */
	public void setUserDetailsChecker(UserDetailsChecker userDetailsChecker) {
		Assert.notNull(userDetailsChecker, "userDetailsChacker cannot be null");
		this.userDetailsChecker = userDetailsChecker;
	}
}
