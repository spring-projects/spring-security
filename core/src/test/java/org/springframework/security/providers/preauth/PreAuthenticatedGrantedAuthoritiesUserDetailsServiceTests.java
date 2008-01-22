package org.springframework.security.providers.preauth;

import org.springframework.security.GrantedAuthorityImpl;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.userdetails.UserDetails;

import java.util.Arrays;
import java.util.Collection;

import junit.framework.TestCase;

/**
 * 
 * @author TSARDD
 * @since 18-okt-2007
 */
public class PreAuthenticatedGrantedAuthoritiesUserDetailsServiceTests extends TestCase {

	public final void testGetUserDetailsInvalidType() {
		PreAuthenticatedGrantedAuthoritiesUserDetailsService svc = new PreAuthenticatedGrantedAuthoritiesUserDetailsService();
		PreAuthenticatedAuthenticationToken token = new PreAuthenticatedAuthenticationToken("dummy", "dummy");
		token.setDetails(new Object());
		try {
			svc.getUserDetails(token);
			fail("Expected exception didn't occur");
		} catch (IllegalArgumentException expected) {
		}
	}

	public final void testGetUserDetailsNoDetails() {
		PreAuthenticatedGrantedAuthoritiesUserDetailsService svc = new PreAuthenticatedGrantedAuthoritiesUserDetailsService();
		PreAuthenticatedAuthenticationToken token = new PreAuthenticatedAuthenticationToken("dummy", "dummy");
		token.setDetails(null);
		try {
			svc.getUserDetails(token);
			fail("Expected exception didn't occur");
		} catch (IllegalArgumentException expected) {
		}
	}

	public final void testGetUserDetailsEmptyAuthorities() {
		final String userName = "dummyUser";
		final GrantedAuthority[] gas = new GrantedAuthority[] {};
		testGetUserDetails(userName, gas);
	}

	public final void testGetUserDetailsWithAuthorities() {
		final String userName = "dummyUser";
		final GrantedAuthority[] gas = new GrantedAuthority[] { new GrantedAuthorityImpl("Role1"), new GrantedAuthorityImpl("Role2") };
		testGetUserDetails(userName, gas);
	}

	private void testGetUserDetails(final String userName, final GrantedAuthority[] gas) {
		PreAuthenticatedGrantedAuthoritiesUserDetailsService svc = new PreAuthenticatedGrantedAuthoritiesUserDetailsService();
		PreAuthenticatedAuthenticationToken token = new PreAuthenticatedAuthenticationToken(userName, "dummy");
		token.setDetails(new PreAuthenticatedGrantedAuthoritiesRetriever() {
			public GrantedAuthority[] getPreAuthenticatedGrantedAuthorities() {
				return gas;
			}
		});
		UserDetails ud = svc.getUserDetails(token);
		assertTrue(ud.isAccountNonExpired());
		assertTrue(ud.isAccountNonLocked());
		assertTrue(ud.isCredentialsNonExpired());
		assertTrue(ud.isEnabled());
		assertEquals(ud.getUsername(), userName);

		//Password is not saved by
		// PreAuthenticatedGrantedAuthoritiesUserDetailsService
		//assertEquals(ud.getPassword(),password);

		Collection expectedColl = Arrays.asList(gas);
		Collection resultColl = Arrays.asList(ud.getAuthorities());
		assertTrue("GrantedAuthority collections do not match; result: " + resultColl + ", expected: " + expectedColl, expectedColl
				.containsAll(resultColl)
				&& resultColl.containsAll(expectedColl));
	}

}
