package org.springframework.security.web.authentication.preauth;

import static org.junit.Assert.*;

import java.util.List;

import org.junit.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.GrantedAuthoritiesContainer;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedGrantedAuthoritiesUserDetailsService;

/**
 *
 * @author TSARDD
 * @since 18-okt-2007
 */
public class PreAuthenticatedGrantedAuthoritiesUserDetailsServiceTests {

    @Test(expected=IllegalArgumentException.class)
    public void testGetUserDetailsInvalidType() {
        PreAuthenticatedGrantedAuthoritiesUserDetailsService svc = new PreAuthenticatedGrantedAuthoritiesUserDetailsService();
        PreAuthenticatedAuthenticationToken token = new PreAuthenticatedAuthenticationToken("dummy", "dummy");
        token.setDetails(new Object());
        svc.loadUserDetails(token);
    }

    @Test(expected=IllegalArgumentException.class)
    public void testGetUserDetailsNoDetails() {
        PreAuthenticatedGrantedAuthoritiesUserDetailsService svc = new PreAuthenticatedGrantedAuthoritiesUserDetailsService();
        PreAuthenticatedAuthenticationToken token = new PreAuthenticatedAuthenticationToken("dummy", "dummy");
        token.setDetails(null);
        svc.loadUserDetails(token);
    }

    @Test
    public void testGetUserDetailsEmptyAuthorities() {
        final String userName = "dummyUser";
        testGetUserDetails(userName, AuthorityUtils.NO_AUTHORITIES);
    }

    @Test
    public void testGetUserDetailsWithAuthorities() {
        final String userName = "dummyUser";
        testGetUserDetails(userName, AuthorityUtils.createAuthorityList("Role1", "Role2"));
    }

    private void testGetUserDetails(final String userName, final List<GrantedAuthority> gas) {
        PreAuthenticatedGrantedAuthoritiesUserDetailsService svc = new PreAuthenticatedGrantedAuthoritiesUserDetailsService();
        PreAuthenticatedAuthenticationToken token = new PreAuthenticatedAuthenticationToken(userName, "dummy");
        token.setDetails(new GrantedAuthoritiesContainer() {
            public List<GrantedAuthority> getGrantedAuthorities() {
                return gas;
            }
        });
        UserDetails ud = svc.loadUserDetails(token);
        assertTrue(ud.isAccountNonExpired());
        assertTrue(ud.isAccountNonLocked());
        assertTrue(ud.isCredentialsNonExpired());
        assertTrue(ud.isEnabled());
        assertEquals(ud.getUsername(), userName);

        //Password is not saved by
        // PreAuthenticatedGrantedAuthoritiesUserDetailsService
        //assertEquals(ud.getPassword(),password);

        assertTrue("GrantedAuthority collections do not match; result: " + ud.getAuthorities() + ", expected: " + gas,
                gas.containsAll(ud.getAuthorities()) && ud.getAuthorities().containsAll(gas));
    }

}
