package org.springframework.security.userdetails.decorator;

import org.springframework.security.userdetails.UserDetailsService;
import org.springframework.security.userdetails.UserDetails;
import org.springframework.security.userdetails.UsernameNotFoundException;
import org.springframework.security.userdetails.User;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.GrantedAuthorityImpl;
import org.springframework.security.LockedException;
import org.springframework.security.DisabledException;
import org.springframework.security.CredentialsExpiredException;
import org.springframework.security.AccountExpiredException;

import org.springframework.dao.DataAccessException;

import org.junit.Test;

import java.util.Map;
import java.util.HashMap;

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

    class MockUserDetailsService implements UserDetailsService {
        private Map <String, UserDetails> users = new HashMap <String, UserDetails>();
        private GrantedAuthority[] auths = new GrantedAuthority[] {new GrantedAuthorityImpl("A")};

        MockUserDetailsService() {
            users.put("valid", new User("valid", "",true,true,true,true,auths));
            users.put("locked", new User("locked", "",true,true,true,false,auths));
            users.put("disabled", new User("disabled", "",false,true,true,true,auths));
            users.put("credentialsExpired", new User("credentialsExpired", "",true,true,false,true,auths));
            users.put("expired", new User("expired", "",true,false,true,true,auths));
        }

        public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException, DataAccessException {
            return users.get(username);
        }
    }
}
