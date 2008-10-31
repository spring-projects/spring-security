package org.springframework.security.ldap.populator;

import java.util.List;

import org.springframework.security.userdetails.UserDetailsService;
import org.springframework.security.userdetails.MockUserDetailsService;
import org.springframework.security.GrantedAuthority;

import org.springframework.ldap.core.DirContextAdapter;

import org.junit.Test;
import static org.junit.Assert.*;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public class UserDetailsServiceLdapAuthoritiesPopulatorTests {
    UserDetailsService uds = new MockUserDetailsService();

    @Test
    public void delegationToUserDetailsServiceReturnsCorrectRoles() throws Exception {
        UserDetailsServiceLdapAuthoritiesPopulator populator = new UserDetailsServiceLdapAuthoritiesPopulator(uds);

        List<GrantedAuthority> auths =  populator.getGrantedAuthorities(new DirContextAdapter(), "valid");

        assertEquals(1, auths.size());
        assertEquals("ROLE_USER", auths.get(0).getAuthority());
    }
}
