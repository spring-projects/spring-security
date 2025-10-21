/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.authentication;

import java.util.Set;

import org.junit.jupiter.api.Test;

import org.springframework.security.core.authority.AuthorityUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests {@link UsernamePasswordAuthenticationToken}.
 *
 * @author Ben Alex
 */
public class UsernamePasswordAuthenticationTokenTests {

	@Test
	public void authenticatedPropertyContractIsSatisfied() {
		UsernamePasswordAuthenticationToken grantedToken = UsernamePasswordAuthenticationToken.authenticated("Test",
				"Password", AuthorityUtils.NO_AUTHORITIES);
		// check default given we passed some GrantedAuthority[]s (well, we passed empty
		// list)
		assertThat(grantedToken.isAuthenticated()).isTrue();
		// check explicit set to untrusted (we can safely go from trusted to untrusted,
		// but not the reverse)
		grantedToken.setAuthenticated(false);
		assertThat(!grantedToken.isAuthenticated()).isTrue();
		// Now let's create a UsernamePasswordAuthenticationToken without any
		// GrantedAuthority[]s (different constructor)
		UsernamePasswordAuthenticationToken noneGrantedToken = UsernamePasswordAuthenticationToken
			.unauthenticated("Test", "Password");
		assertThat(!noneGrantedToken.isAuthenticated()).isTrue();
		// check we're allowed to still set it to untrusted
		noneGrantedToken.setAuthenticated(false);
		assertThat(!noneGrantedToken.isAuthenticated()).isTrue();
		// check denied changing it to trusted
		assertThatIllegalArgumentException().isThrownBy(() -> noneGrantedToken.setAuthenticated(true));
	}

	@Test
	public void gettersReturnCorrectData() {
		UsernamePasswordAuthenticationToken token = UsernamePasswordAuthenticationToken.authenticated("Test",
				"Password", AuthorityUtils.createAuthorityList("ROLE_ONE", "ROLE_TWO"));
		assertThat(token.getPrincipal()).isEqualTo("Test");
		assertThat(token.getCredentials()).isEqualTo("Password");
		assertThat(AuthorityUtils.authorityListToSet(token.getAuthorities())).contains("ROLE_ONE");
		assertThat(AuthorityUtils.authorityListToSet(token.getAuthorities())).contains("ROLE_TWO");
	}

	@Test
	public void testNoArgConstructorDoesntExist() throws Exception {
		Class<?> clazz = UsernamePasswordAuthenticationToken.class;
		assertThatExceptionOfType(NoSuchMethodException.class)
			.isThrownBy(() -> clazz.getDeclaredConstructor((Class[]) null));
	}

	@Test
	public void unauthenticatedFactoryMethodResultsUnauthenticatedToken() {
		UsernamePasswordAuthenticationToken grantedToken = UsernamePasswordAuthenticationToken.unauthenticated("Test",
				"Password");
		assertThat(grantedToken.isAuthenticated()).isFalse();
	}

	@Test
	public void authenticatedFactoryMethodResultsAuthenticatedToken() {
		UsernamePasswordAuthenticationToken grantedToken = UsernamePasswordAuthenticationToken.authenticated("Test",
				"Password", AuthorityUtils.NO_AUTHORITIES);
		assertThat(grantedToken.isAuthenticated()).isTrue();
	}

	@Test
	public void toBuilderWhenApplyThenCopies() {
		UsernamePasswordAuthenticationToken factorOne = new UsernamePasswordAuthenticationToken("alice", "pass",
				AuthorityUtils.createAuthorityList("FACTOR_ONE"));
		UsernamePasswordAuthenticationToken factorTwo = new UsernamePasswordAuthenticationToken("bob", "ssap",
				AuthorityUtils.createAuthorityList("FACTOR_TWO"));
		UsernamePasswordAuthenticationToken result = factorOne.toBuilder()
			.authorities((a) -> a.addAll(factorTwo.getAuthorities()))
			.principal(factorTwo.getPrincipal())
			.credentials(factorTwo.getCredentials())
			.build();
		Set<String> authorities = AuthorityUtils.authorityListToSet(result.getAuthorities());
		assertThat(result.getPrincipal()).isEqualTo("bob");
		assertThat(result.getCredentials()).isEqualTo("ssap");
		assertThat(authorities).containsExactlyInAnyOrder("FACTOR_ONE", "FACTOR_TWO");
	}

}
