package org.springframework.security.userdetails.checker;

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
    }
}
