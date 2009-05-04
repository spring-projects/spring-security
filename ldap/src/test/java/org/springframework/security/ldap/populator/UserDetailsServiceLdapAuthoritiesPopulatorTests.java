package org.springframework.security.ldap.populator;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.*;

import java.util.List;

import org.junit.Test;
import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.ldap.authentication.UserDetailsServiceLdapAuthoritiesPopulator;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public class UserDetailsServiceLdapAuthoritiesPopulatorTests {

    @Test
    public void delegationToUserDetailsServiceReturnsCorrectRoles() throws Exception {
        UserDetailsService uds = mock(UserDetailsService.class);
        UserDetails user = mock(UserDetails.class);
        when(uds.loadUserByUsername("joe")).thenReturn(user);
        when(user.getAuthorities()).thenReturn(AuthorityUtils.createAuthorityList("ROLE_USER"));

        UserDetailsServiceLdapAuthoritiesPopulator populator = new UserDetailsServiceLdapAuthoritiesPopulator(uds);
        List<GrantedAuthority> auths =  populator.getGrantedAuthorities(new DirContextAdapter(), "joe");

        assertEquals(1, auths.size());
        assertEquals("ROLE_USER", auths.get(0).getAuthority());
    }
}
