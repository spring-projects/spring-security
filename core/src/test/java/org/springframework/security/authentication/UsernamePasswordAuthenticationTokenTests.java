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

import org.junit.Test;

import org.springframework.security.core.authority.AuthorityUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

/**
 * Tests {@link UsernamePasswordAuthenticationToken}.
 *
 * @author Ben Alex
 */
public class UsernamePasswordAuthenticationTokenTests {

	@Test
	public void authenticatedPropertyContractIsSatisfied() {
		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("Test", "Password",
				AuthorityUtils.NO_AUTHORITIES);
		// check default given we passed some GrantedAuthorty[]s (well, we passed empty
		// list)
		assertThat(token.isAuthenticated()).isTrue();
		// check explicit set to untrusted (we can safely go from trusted to untrusted,
		// but not the reverse)
		token.setAuthenticated(false);
		assertThat(!token.isAuthenticated()).isTrue();
		// Now let's create a UsernamePasswordAuthenticationToken without any
		// GrantedAuthorty[]s (different constructor)
		token = new UsernamePasswordAuthenticationToken("Test", "Password");
		assertThat(!token.isAuthenticated()).isTrue();
		// check we're allowed to still set it to untrusted
		token.setAuthenticated(false);
		assertThat(!token.isAuthenticated()).isTrue();
		// check denied changing it to trusted
		try {
			token.setAuthenticated(true);
			fail("Should have prohibited setAuthenticated(true)");
		}
		catch (IllegalArgumentException expected) {
		}
	}

	@Test
	public void gettersReturnCorrectData() {
		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("Test", "Password",
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
