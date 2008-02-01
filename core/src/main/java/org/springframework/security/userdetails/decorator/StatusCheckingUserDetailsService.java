package org.springframework.security.userdetails.decorator;

import org.springframework.security.userdetails.UserDetailsService;
import org.springframework.security.userdetails.UserDetails;
import org.springframework.security.LockedException;
import org.springframework.security.DisabledException;
import org.springframework.security.AccountExpiredException;
import org.springframework.security.CredentialsExpiredException;
import org.springframework.security.SpringSecurityMessageSource;
import org.springframework.security.AuthenticationException;
import org.springframework.dao.DataAccessException;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.util.Assert;

/**
 * Decorates a {@link UserDetailsService}, making it throw an exception if the account is locked, disabled etc. This
 * removes the need for separate account status checks in classes which make use of a <tt>UserDetailsService</tt>. 
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class StatusCheckingUserDetailsService implements UserDetailsService {
    private UserDetailsService delegate;

    protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

    public StatusCheckingUserDetailsService(UserDetailsService userDetailsService) {
        this.delegate = userDetailsService;
    }

    public UserDetails loadUserByUsername(String username) throws AuthenticationException, DataAccessException {

        UserDetails user = delegate.loadUserByUsername(username);

        Assert.notNull(user, "UserDetailsService returned null user, an interface violation.");

        if (!user.isAccountNonLocked()) {
            throw new LockedException(messages.getMessage("UserDetailsService.locked", "User account is locked"));
        }

        if (!user.isEnabled()) {
            throw new DisabledException(messages.getMessage("UserDetailsService.disabled", "User is disabled"));
        }

        if (!user.isAccountNonExpired()) {
            throw new AccountExpiredException(messages.getMessage("UserDetailsService.expired",
                    "User account has expired"));
        }

        if (!user.isCredentialsNonExpired()) {
            throw new CredentialsExpiredException(messages.getMessage("UserDetailsService.credentialsExpired",
                    "User credentials have expired"));
        }

        return user;
    }
}
