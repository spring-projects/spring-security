package org.springframework.security.userdetails.ldap;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.List;
import java.util.Set;

import org.junit.Test;
import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.DistinguishedName;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.ldap.LdapAuthoritiesPopulator;
import org.springframework.security.providers.ldap.authenticator.MockUserSearch;
import org.springframework.security.userdetails.UserDetails;
import org.springframework.security.util.AuthorityUtils;

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

        Set authorities = AuthorityUtils.authorityListToSet(user.getAuthorities());
        assertEquals(1, authorities.size());
        assertTrue(authorities.contains("ROLE_FROM_POPULATOR"));
    }

    class MockAuthoritiesPopulator implements LdapAuthoritiesPopulator {
        public List<GrantedAuthority> getGrantedAuthorities(DirContextOperations userCtx, String username) {
            return AuthorityUtils.createAuthorityList("ROLE_FROM_POPULATOR");
        }
    }
}
