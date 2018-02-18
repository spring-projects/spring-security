package org.springframework.security.authentication;

import org.junit.Test;
import org.springframework.security.core.authority.AuthorityUtils;

import static org.assertj.core.api.Assertions.assertThat;

public class FirstOfMultiFactorAuthenticationTokenTests {
	// ~ Methods
	// ========================================================================================================

	@Test
	public void authenticatedPropertyContractIsSatisfied() {
		FirstOfMultiFactorAuthenticationToken token = new FirstOfMultiFactorAuthenticationToken(
			"Test", "Password", AuthorityUtils.NO_AUTHORITIES);

		// check default given we passed some GrantedAuthority[]s (well, we passed empty
		// list)
		assertThat(token.isAuthenticated()).isTrue();

		// check explicit set to untrusted (we can safely go from trusted to untrusted,
		// but not the reverse)
		token.setAuthenticated(false);
		assertThat(token.isAuthenticated()).isFalse();

	}

	@Test
	public void gettersReturnCorrectData() {
		FirstOfMultiFactorAuthenticationToken token = new FirstOfMultiFactorAuthenticationToken(
			"Test", "Password",
			AuthorityUtils.createAuthorityList("ROLE_ONE", "ROLE_TWO"));
		assertThat(token.getPrincipal()).isEqualTo("Test");
		assertThat(token.getCredentials()).isEqualTo("Password");
		assertThat(AuthorityUtils.authorityListToSet(token.getAuthorities())).contains("ROLE_ONE");
		assertThat(AuthorityUtils.authorityListToSet(token.getAuthorities())).contains("ROLE_TWO");
	}

	@Test(expected = NoSuchMethodException.class)
	public void testNoArgConstructorDoesntExist() throws Exception {
		Class<?> clazz = UsernamePasswordAuthenticationToken.class;
		clazz.getDeclaredConstructor((Class[]) null);
	}

}
