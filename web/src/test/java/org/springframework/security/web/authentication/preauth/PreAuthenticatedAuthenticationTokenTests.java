package org.springframework.security.web.authentication.preauth;

import java.util.Collection;
import java.util.List;

import junit.framework.TestCase;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

/**
 *
 * @author TSARDD
 * @since 18-okt-2007
 */
public class PreAuthenticatedAuthenticationTokenTests extends TestCase {

	public void testPreAuthenticatedAuthenticationTokenRequestWithDetails() {
		Object principal = "dummyUser";
		Object credentials = "dummyCredentials";
		Object details = "dummyDetails";
		PreAuthenticatedAuthenticationToken token = new PreAuthenticatedAuthenticationToken(
				principal, credentials);
		token.setDetails(details);
		assertThat(token.getPrincipal()).isEqualTo(principal);
		assertThat(token.getCredentials()).isEqualTo(credentials);
		assertThat(token.getDetails()).isEqualTo(details);
		assertThat(token.getAuthorities().isEmpty()).isTrue();
	}

	public void testPreAuthenticatedAuthenticationTokenRequestWithoutDetails() {
		Object principal = "dummyUser";
		Object credentials = "dummyCredentials";
		PreAuthenticatedAuthenticationToken token = new PreAuthenticatedAuthenticationToken(
				principal, credentials);
		assertThat(token.getPrincipal()).isEqualTo(principal);
		assertThat(token.getCredentials()).isEqualTo(credentials);
		assertThat(token.getDetails()).isNull();
		assertThat(token.getAuthorities().isEmpty()).isTrue();
	}

	public void testPreAuthenticatedAuthenticationTokenResponse() {
		Object principal = "dummyUser";
		Object credentials = "dummyCredentials";
		List<GrantedAuthority> gas = AuthorityUtils.createAuthorityList("Role1");
		PreAuthenticatedAuthenticationToken token = new PreAuthenticatedAuthenticationToken(
				principal, credentials, gas);
		assertThat(token.getPrincipal()).isEqualTo(principal);
		assertThat(token.getCredentials()).isEqualTo(credentials);
		assertThat(token.getDetails()).isNull();
		assertThat(token.getAuthorities()).isNotNull();
		Collection<GrantedAuthority> resultColl = token.getAuthorities();
		assertTrue("GrantedAuthority collections do not match; result: " + resultColl
				+ ", expected: " + gas,
				gas.containsAll(resultColl) && resultColl.containsAll(gas));

	}

}
