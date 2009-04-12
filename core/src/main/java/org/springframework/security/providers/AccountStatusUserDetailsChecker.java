package org.springframework.security.providers;

import org.springframework.security.userdetails.UserDetailsChecker;
import org.springframework.security.userdetails.UserDetails;
import org.springframework.security.LockedException;
import org.springframework.security.DisabledException;
import org.springframework.security.AccountExpiredException;
import org.springframework.security.CredentialsExpiredException;
import org.springframework.security.SpringSecurityMessageSource;
import org.springframework.context.support.MessageSourceAccessor;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public class AccountStatusUserDetailsChecker implements UserDetailsChecker {

    protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

    public void check(UserDetails user) {
        if (!user.isAccountNonLocked()) {
            throw new LockedException(messages.getMessage("UserDetailsService.locked", "User account is locked"), user);
        }

        if (!user.isEnabled()) {
            throw new DisabledException(messages.getMessage("UserDetailsService.disabled", "User is disabled"), user);
        }

        if (!user.isAccountNonExpired()) {
            throw new AccountExpiredException(messages.getMessage("UserDetailsService.expired",
                    "User account has expired"), user);
        }

        if (!user.isCredentialsNonExpired()) {
            throw new CredentialsExpiredException(messages.getMessage("UserDetailsService.credentialsExpired",
                    "User credentials have expired"), user);
        }
    }
}
