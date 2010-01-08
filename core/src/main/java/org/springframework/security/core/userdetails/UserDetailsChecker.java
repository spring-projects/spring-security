package org.springframework.security.core.userdetails;

/**
 * Called by classes which make use of a {@link UserDetailsService} to check the status of the loaded
 * <tt>UserDetails</tt> object. Typically this will involve examining the various flags associated with the account and
 * raising an exception if the information cannot be used (for example if the user account is locked or disabled), but
 * a custom implementation could perform any checks it wished.
 * <p>
 * The intention is that this interface should only be used for checks on the persistent data associated with the user.
 * It should not involved in making any authentication decisions based on a submitted authentication request.
 *
 * @author Luke Taylor
 * @since 2.0
 *
 * @see org.springframework.security.authentication.AccountStatusUserDetailsChecker
 * @see org.springframework.security.authentication.AccountStatusException
 */
public interface UserDetailsChecker {
    /**
     * Examines the User
     * @param toCheck the UserDetails instance whose status should be checked.
     */
    void check(UserDetails toCheck);
}
