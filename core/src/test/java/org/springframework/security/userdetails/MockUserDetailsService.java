package org.springframework.security.userdetails;

import org.springframework.security.GrantedAuthority;
import org.springframework.security.GrantedAuthorityImpl;
import org.springframework.dao.DataAccessException;

import java.util.Map;
import java.util.HashMap;

/**
 * A test UserDetailsService containing a set of standard usernames corresponding to their account status:
 * valid, locked, disabled, credentialsExpired, expired. All passwords are "".
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class MockUserDetailsService implements UserDetailsService {
    private Map users = new HashMap();
    private GrantedAuthority[] auths = new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_USER")};

    public MockUserDetailsService() {
        users.put("valid", new User("valid", "",true,true,true,true,auths));
        users.put("locked", new User("locked", "",true,true,true,false,auths));
        users.put("disabled", new User("disabled", "",false,true,true,true,auths));
        users.put("credentialsExpired", new User("credentialsExpired", "",true,true,false,true,auths));
        users.put("expired", new User("expired", "",true,false,true,true,auths));
    }

    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException, DataAccessException {
        if (users.get(username) == null) {
            throw new UsernameNotFoundException("User not found: " + username);
        }

        return (UserDetails) users.get(username);
    }
}
