package org.springframework.security.userdetails.decorator;

import org.springframework.security.userdetails.MockUserDetailsService;
import org.springframework.security.LockedException;
import org.springframework.security.DisabledException;
import org.springframework.security.CredentialsExpiredException;
import org.springframework.security.AccountExpiredException;

import org.junit.Test;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public class StatusCheckingUserDetailsServiceTests {
    private StatusCheckingUserDetailsService us = new StatusCheckingUserDetailsService(new MockUserDetailsService());

    @Test
    public void validAccountIsSuccessfullyLoaded() throws Exception {
        us.loadUserByUsername("valid");
    }

    @Test(expected = LockedException.class)
    public void lockedAccountThrowsLockedException() throws Exception {
        us.loadUserByUsername("locked");
    }

    @Test(expected = DisabledException.class)
    public void disabledAccountThrowsDisabledException() throws Exception {
        us.loadUserByUsername("disabled");
    }

    @Test(expected = CredentialsExpiredException.class)
    public void credentialsExpiredAccountThrowsCredentialsExpiredException() throws Exception {
        us.loadUserByUsername("credentialsExpired");
    }

    @Test(expected = AccountExpiredException.class)
    public void expiredAccountThrowsAccountExpiredException() throws Exception {
        us.loadUserByUsername("expired");
    }

}
