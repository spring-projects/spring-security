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

package org.springframework.security.access.intercept;

import org.junit.Test;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

/**
 * Tests {@link RunAsUserToken}.
 *
 * @author Ben Alex
 */
public class RunAsUserTokenTests {

	@Test
	public void testAuthenticationSetting() {
		RunAsUserToken token = new RunAsUserToken("my_password", "Test", "Password",
				AuthorityUtils.createAuthorityList("ROLE_ONE", "ROLE_TWO"), UsernamePasswordAuthenticationToken.class);
		assertThat(token.isAuthenticated()).isTrue();
		token.setAuthenticated(false);
		assertThat(!token.isAuthenticated()).isTrue();
	}

	@Test
	public void testGetters() {
		RunAsUserToken token = new RunAsUserToken("my_password", "Test", "Password",
				AuthorityUtils.createAuthorityList("ROLE_ONE", "ROLE_TWO"), UsernamePasswordAuthenticationToken.class);
		assertThat("Test").isEqualTo(token.getPrincipal());
		assertThat("Password").isEqualTo(token.getCredentials());
		assertThat("my_password".hashCode()).isEqualTo(token.getKeyHash());
		assertThat(UsernamePasswordAuthenticationToken.class).isEqualTo(token.getOriginalAuthentication());
	}

	@Test
	public void testNoArgConstructorDoesntExist() {
		Class<RunAsUserToken> clazz = RunAsUserToken.class;

		try {
			clazz.getDeclaredConstructor((Class[]) null);
			fail("Should have thrown NoSuchMethodException");
		}
		catch (NoSuchMethodException expected) {
			assertThat(true).isTrue();
		}
	}

	@Test
	public void testToString() {
		RunAsUserToken token = new RunAsUserToken("my_password", "Test", "Password",
				AuthorityUtils.createAuthorityList("ROLE_ONE", "ROLE_TWO"), UsernamePasswordAuthenticationToken.class);
		assertThat(token.toString()
				.lastIndexOf("Original Class: " + UsernamePasswordAuthenticationToken.class.getName().toString()) != -1)
						.isTrue();
	}

	// SEC-1792
	@Test
	public void testToStringNullOriginalAuthentication() {
		RunAsUserToken token = new RunAsUserToken("my_password", "Test", "Password",
				AuthorityUtils.createAuthorityList("ROLE_ONE", "ROLE_TWO"), null);
		assertThat(token.toString().lastIndexOf("Original Class: null") != -1).isTrue();
	}

}
