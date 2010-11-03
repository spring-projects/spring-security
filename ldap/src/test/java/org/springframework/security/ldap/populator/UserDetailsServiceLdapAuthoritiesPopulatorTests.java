package org.springframework.security.ldap.populator;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import java.util.Collection;
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
 */
public class UserDetailsServiceLdapAuthoritiesPopulatorTests {

    @Test
    public void delegationToUserDetailsServiceReturnsCorrectRoles() throws Exception {
        UserDetailsService uds = mock(UserDetailsService.class);
        UserDetails user = mock(UserDetails.class);
        when(uds.loadUserByUsername("joe")).thenReturn(user);
        List authorities = AuthorityUtils.createAuthorityList("ROLE_USER");
        when(user.getAuthorities()).thenReturn(authorities);

        UserDetailsServiceLdapAuthoritiesPopulator populator = new UserDetailsServiceLdapAuthoritiesPopulator(uds);
        Collection<? extends GrantedAuthority> auths =  populator.getGrantedAuthorities(new DirContextAdapter(), "joe");

        assertEquals(1, auths.size());
        assertTrue(AuthorityUtils.authorityListToSet(auths).contains("ROLE_USER"));
    }
}
