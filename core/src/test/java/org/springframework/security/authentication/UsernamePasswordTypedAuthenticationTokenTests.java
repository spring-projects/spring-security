package org.springframework.security.authentication;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;

import static org.assertj.core.api.Assertions.*;

/**
 * Tests {@link UsernamePasswordTypedAuthenticationToken}.
 * Replicates {@link UsernamePasswordAuthenticationTokenTests}
 * @author Peter Eastham
 */
public class UsernamePasswordTypedAuthenticationTokenTests {

	@Test
	public void authenticatedPropertyContractIsSatisfied() {
		User simpleUser = new User("Test", "Password", AuthorityUtils.NO_AUTHORITIES);
		UsernamePasswordTypedAuthenticationToken<Object> grantedToken = UsernamePasswordTypedAuthenticationToken
			.authenticated(simpleUser, simpleUser.getPassword());
		// check default given we passed some GrantedAuthority[]s (well, we passed empty
		// list)
		assertThat(grantedToken.isAuthenticated()).isTrue();
		// check explicit set to untrusted (we can safely go from trusted to untrusted,
		// but not the reverse)
		grantedToken.setAuthenticated(false);
		assertThat(!grantedToken.isAuthenticated()).isTrue();
		// Now let's create a UsernamePasswordAuthenticationToken without any
		// GrantedAuthority[]s (different constructor)
		UsernamePasswordTypedAuthenticationToken<Object> noneGrantedToken = UsernamePasswordTypedAuthenticationToken
			.unauthenticated(simpleUser, simpleUser.getPassword());
		assertThat(!noneGrantedToken.isAuthenticated()).isTrue();
		// check we're allowed to still set it to untrusted
		noneGrantedToken.setAuthenticated(false);
		assertThat(!noneGrantedToken.isAuthenticated()).isTrue();
		// check denied changing it to trusted
		assertThatIllegalArgumentException().isThrownBy(() -> noneGrantedToken.setAuthenticated(true));
	}

	@Test
	public void gettersReturnCorrectData() {
		User simpleUser = new User("Test", "Password", AuthorityUtils.createAuthorityList("ROLE_ONE", "ROLE_TWO"));
		UsernamePasswordTypedAuthenticationToken<Object> token = UsernamePasswordTypedAuthenticationToken
			.authenticated(simpleUser, simpleUser.getPassword());
		assertThat(token.getName()).isEqualTo("Test");
		assertThat(token.getPrincipal().getUsername()).isEqualTo("Test");
		assertThat(token.getCredentials()).isEqualTo("Password");
		assertThat(AuthorityUtils.authorityListToSet(token.getAuthorities())).contains("ROLE_ONE");
		assertThat(AuthorityUtils.authorityListToSet(token.getAuthorities())).contains("ROLE_TWO");
	}

	@Test
	public void testNoArgConstructorDoesntExist() throws Exception {
		Class<?> clazz = UsernamePasswordTypedAuthenticationToken.class;
		assertThatExceptionOfType(NoSuchMethodException.class)
			.isThrownBy(() -> clazz.getDeclaredConstructor((Class[]) null));
	}

	@Test
	public void unauthenticatedFactoryMethodResultsUnauthenticatedToken() {
		User simpleUser = new User("Test", "Password", AuthorityUtils.NO_AUTHORITIES);
		UsernamePasswordTypedAuthenticationToken<Object> grantedToken = UsernamePasswordTypedAuthenticationToken
			.unauthenticated(simpleUser, simpleUser.getPassword());
		assertThat(grantedToken.isAuthenticated()).isFalse();
	}

	@Test
	public void authenticatedFactoryMethodResultsAuthenticatedToken() {
		User simpleUser = new User("Test", "Password", AuthorityUtils.NO_AUTHORITIES);
		UsernamePasswordTypedAuthenticationToken<Object> grantedToken = UsernamePasswordTypedAuthenticationToken
			.authenticated(simpleUser, simpleUser.getPassword());
		assertThat(grantedToken.isAuthenticated()).isTrue();
	}

}
