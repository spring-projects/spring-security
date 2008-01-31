package org.springframework.security.providers.preauth;

import org.springframework.security.providers.UsernamePasswordAuthenticationToken;
import org.springframework.security.userdetails.User;
import org.springframework.security.userdetails.UserDetails;
import org.springframework.security.userdetails.UsernameNotFoundException;
import org.springframework.security.Authentication;
import org.springframework.security.GrantedAuthority;

import junit.framework.TestCase;

/**
 * 
 * @author TSARDD
 * @since 18-okt-2007
 */
public class PreAuthenticatedAuthenticationProviderTests extends TestCase {
	private static final String SUPPORTED_USERNAME = "dummyUser";

	public final void testAfterPropertiesSet() {
		PreAuthenticatedAuthenticationProvider provider = new PreAuthenticatedAuthenticationProvider();
		try {
			provider.afterPropertiesSet();
			fail("AfterPropertiesSet didn't throw expected exception");
		} catch (IllegalArgumentException expected) {
		} catch (Exception unexpected) {
			fail("AfterPropertiesSet throws unexpected exception");
		}
	}

	public final void testAuthenticateInvalidToken() throws Exception {
		UserDetails ud = new User("dummyUser", "dummyPwd", true, true, true, true, new GrantedAuthority[] {});
		PreAuthenticatedAuthenticationProvider provider = getProvider(ud);
		Authentication request = new UsernamePasswordAuthenticationToken("dummyUser", "dummyPwd");
		Authentication result = provider.authenticate(request);
		assertNull(result);
	}

    public final void testNullPrincipalReturnsNullAuthentication() throws Exception {
        PreAuthenticatedAuthenticationProvider provider = new PreAuthenticatedAuthenticationProvider();
        Authentication request = new PreAuthenticatedAuthenticationToken(null, "dummyPwd");
        Authentication result = provider.authenticate(request);
        assertNull(result);
    }

    public final void testAuthenticateKnownUser() throws Exception {
		UserDetails ud = new User("dummyUser", "dummyPwd", true, true, true, true, new GrantedAuthority[] {});
		PreAuthenticatedAuthenticationProvider provider = getProvider(ud);
		Authentication request = new PreAuthenticatedAuthenticationToken("dummyUser", "dummyPwd");
		Authentication result = provider.authenticate(request);
		assertNotNull(result);
		assertEquals(result.getPrincipal(), ud);
		// @TODO: Add more asserts?
	}

	public final void testAuthenticateIgnoreCredentials() throws Exception {
		UserDetails ud = new User("dummyUser1", "dummyPwd1", true, true, true, true, new GrantedAuthority[] {});
		PreAuthenticatedAuthenticationProvider provider = getProvider(ud);
		Authentication request = new PreAuthenticatedAuthenticationToken("dummyUser1", "dummyPwd2");
		Authentication result = provider.authenticate(request);
		assertNotNull(result);
		assertEquals(result.getPrincipal(), ud);
		// @TODO: Add more asserts?
	}

	public final void testAuthenticateUnknownUser() throws Exception {
		UserDetails ud = new User("dummyUser1", "dummyPwd", true, true, true, true, new GrantedAuthority[] {});
		PreAuthenticatedAuthenticationProvider provider = getProvider(ud);
		Authentication request = new PreAuthenticatedAuthenticationToken("dummyUser2", "dummyPwd");
		Authentication result = provider.authenticate(request);
		assertNull(result);
	}

	public final void testSupportsArbitraryObject() throws Exception {
		PreAuthenticatedAuthenticationProvider provider = getProvider(null);
		assertFalse(provider.supports(Authentication.class));
	}

	public final void testSupportsPreAuthenticatedAuthenticationToken() throws Exception {
		PreAuthenticatedAuthenticationProvider provider = getProvider(null);
		assertTrue(provider.supports(PreAuthenticatedAuthenticationToken.class));
	}

	public void testGetSetOrder() throws Exception {
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

	private AuthenticationUserDetailsService getPreAuthenticatedUserDetailsService(final UserDetails aUserDetails) {
		return new AuthenticationUserDetailsService() {
			public UserDetails loadUserDetails(Authentication token) throws UsernameNotFoundException {
				if (aUserDetails != null && aUserDetails.getUsername().equals(token.getName())) {
					return aUserDetails;
				} else {
					return null;
				}
			}
		};
	}

}
