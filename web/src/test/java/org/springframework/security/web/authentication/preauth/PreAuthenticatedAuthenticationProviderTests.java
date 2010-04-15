package org.springframework.security.web.authentication.preauth;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

/**
 *
 * @author TSARDD
 * @since 18-okt-2007
 */
public class PreAuthenticatedAuthenticationProviderTests {

    @Test(expected = IllegalArgumentException.class)
    public final void afterPropertiesSet() {
        PreAuthenticatedAuthenticationProvider provider = new PreAuthenticatedAuthenticationProvider();

        provider.afterPropertiesSet();
    }

    @Test
    public final void authenticateInvalidToken() throws Exception {
        UserDetails ud = new User("dummyUser", "dummyPwd", true, true, true, true, AuthorityUtils.NO_AUTHORITIES );
        PreAuthenticatedAuthenticationProvider provider = getProvider(ud);
        Authentication request = new UsernamePasswordAuthenticationToken("dummyUser", "dummyPwd");
        Authentication result = provider.authenticate(request);
        assertNull(result);
    }

    @Test
    public final void nullPrincipalReturnsNullAuthentication() throws Exception {
        PreAuthenticatedAuthenticationProvider provider = new PreAuthenticatedAuthenticationProvider();
        Authentication request = new PreAuthenticatedAuthenticationToken(null, "dummyPwd");
        Authentication result = provider.authenticate(request);
        assertNull(result);
    }

    @Test
    public final void authenticateKnownUser() throws Exception {
        UserDetails ud = new User("dummyUser", "dummyPwd", true, true, true, true, AuthorityUtils.NO_AUTHORITIES );
        PreAuthenticatedAuthenticationProvider provider = getProvider(ud);
        Authentication request = new PreAuthenticatedAuthenticationToken("dummyUser", "dummyPwd");
        Authentication result = provider.authenticate(request);
        assertNotNull(result);
        assertEquals(result.getPrincipal(), ud);
        // @TODO: Add more asserts?
    }

    @Test
    public final void authenticateIgnoreCredentials() throws Exception {
        UserDetails ud = new User("dummyUser1", "dummyPwd1", true, true, true, true, AuthorityUtils.NO_AUTHORITIES );
        PreAuthenticatedAuthenticationProvider provider = getProvider(ud);
        Authentication request = new PreAuthenticatedAuthenticationToken("dummyUser1", "dummyPwd2");
        Authentication result = provider.authenticate(request);
        assertNotNull(result);
        assertEquals(result.getPrincipal(), ud);
        // @TODO: Add more asserts?
    }

    @Test(expected=UsernameNotFoundException.class)
    public final void authenticateUnknownUserThrowsException() throws Exception {
        UserDetails ud = new User("dummyUser1", "dummyPwd", true, true, true, true, AuthorityUtils.NO_AUTHORITIES );
        PreAuthenticatedAuthenticationProvider provider = getProvider(ud);
        Authentication request = new PreAuthenticatedAuthenticationToken("dummyUser2", "dummyPwd");
        provider.authenticate(request);
    }

    @Test
    public final void supportsArbitraryObject() throws Exception {
        PreAuthenticatedAuthenticationProvider provider = getProvider(null);
        assertFalse(provider.supports(Authentication.class));
    }

    @Test
    public final void supportsPreAuthenticatedAuthenticationToken() throws Exception {
        PreAuthenticatedAuthenticationProvider provider = getProvider(null);
        assertTrue(provider.supports(PreAuthenticatedAuthenticationToken.class));
    }

    @Test
    public void getSetOrder() throws Exception {
        PreAuthenticatedAuthenticationProvider provider = getProvider(null);
        provider.setOrder(333);
        assertEquals(provider.getOrder(), 333);
    }

    private PreAuthenticatedAuthenticationProvider getProvider(UserDetails aUserDetails) throws Exception {
        PreAuthenticatedAuthenticationProvider result = new PreAuthenticatedAuthenticationProvider();
        result.setPreAuthenticatedUserDetailsService(getPreAuthenticatedUserDetailsService(aUserDetails));
        result.afterPropertiesSet();
        return result;
    }

    private AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken>
            getPreAuthenticatedUserDetailsService(final UserDetails aUserDetails) {
        return new AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken>() {
            public UserDetails loadUserDetails(PreAuthenticatedAuthenticationToken token) throws UsernameNotFoundException {
                if (aUserDetails != null && aUserDetails.getUsername().equals(token.getName())) {
                    return aUserDetails;
                }

                throw new UsernameNotFoundException("notfound");
            }
        };
    }

}
