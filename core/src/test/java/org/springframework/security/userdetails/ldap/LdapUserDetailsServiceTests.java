package org.springframework.security.userdetails.ldap;

import org.springframework.security.GrantedAuthority;
import org.springframework.security.GrantedAuthorityImpl;
import org.springframework.security.ldap.LdapAuthoritiesPopulator;
import org.springframework.security.providers.ldap.authenticator.MockUserSearch;
import org.springframework.security.userdetails.UserDetails;
import org.springframework.security.util.AuthorityUtils;
import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.DistinguishedName;

import static org.junit.Assert.*;
import org.junit.Test;

import java.util.Set;

/**
 * Tests for {@link LdapUserDetailsService}
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class LdapUserDetailsServiceTests {

    @Test(expected = IllegalArgumentException.class)
    public void rejectsNullSearchObject() {
        new LdapUserDetailsService(null, new MockAuthoritiesPopulator());
    }

    @Test(expected = IllegalArgumentException.class)
    public void rejectsNullAuthoritiesPopulator() {
        new LdapUserDetailsService(new MockUserSearch(), null);
    }

    @Test
    public void correctAuthoritiesAreReturned() {
        DirContextAdapter userData = new DirContextAdapter(new DistinguishedName("uid=joe"));

        LdapUserDetailsService service =
                new LdapUserDetailsService(new MockUserSearch(userData), new MockAuthoritiesPopulator());
        service.setUserDetailsMapper(new LdapUserDetailsMapper());

        UserDetails user = service.loadUserByUsername("doesntmatterwegetjoeanyway");

        Set authorities = AuthorityUtils.authorityArrayToSet(user.getAuthorities());
        assertEquals(1, authorities.size());
        assertTrue(authorities.contains("ROLE_FROM_POPULATOR"));
    }

    class MockAuthoritiesPopulator implements LdapAuthoritiesPopulator {
        public GrantedAuthority[] getGrantedAuthorities(DirContextOperations userCtx, String username) {
            return new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_FROM_POPULATOR")};
        }
    }
}
