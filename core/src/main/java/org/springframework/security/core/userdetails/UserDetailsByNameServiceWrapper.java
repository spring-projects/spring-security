package org.springframework.security.core.userdetails;

import org.springframework.security.core.Authentication;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.dao.DataAccessException;
import org.springframework.util.Assert;

/**
 * This implementation for AuthenticationUserDetailsService wraps a regular
 * Spring Security UserDetailsService implementation, to retrieve a UserDetails object
 * based on the user name contained in an <tt>Authentication</tt> object.
 *
 * @author Ruud Senden
 * @author Scott Battaglia
 * @since 2.0
 */
public class UserDetailsByNameServiceWrapper implements AuthenticationUserDetailsService, InitializingBean {
    private UserDetailsService userDetailsService = null;

    /**
     * Constructs an empty wrapper for compatibility with Spring Security 2.0.x's method of using a setter.
     */
    public UserDetailsByNameServiceWrapper() {
        // constructor for backwards compatibility with 2.0
    }

    /**
     * Constructs a new wrapper using the supplied {@link org.springframework.security.core.userdetails.UserDetailsService}
     * as the service to delegate to.
     *
     * @param userDetailsService the UserDetailsService to delegate to.
     */
    public UserDetailsByNameServiceWrapper(final UserDetailsService userDetailsService) {
        Assert.notNull(userDetailsService, "userDetailsService cannot be null.");
        this.userDetailsService = userDetailsService;
    }

    /**
     * Check whether all required properties have been set.
     *
     * @see org.springframework.beans.factory.InitializingBean#afterPropertiesSet()
     */
    public void afterPropertiesSet() throws Exception {
        Assert.notNull(this.userDetailsService, "UserDetailsService must be set");
    }

    /**
     * Get the UserDetails object from the wrapped UserDetailsService
     * implementation
     */
    public UserDetails loadUserDetails(Authentication authentication) throws UsernameNotFoundException,
            DataAccessException {
        return this.userDetailsService.loadUserByUsername(authentication.getName());
    }

    /**
     * Set the wrapped UserDetailsService implementation
     *
     * @param aUserDetailsService
     *            The wrapped UserDetailsService to set
     */
    public void setUserDetailsService(UserDetailsService aUserDetailsService) {
        this.userDetailsService = aUserDetailsService;
    }
}
