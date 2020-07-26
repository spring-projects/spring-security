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

package org.springframework.security.authentication.rcp;

import java.util.Collection;

import org.junit.Test;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

/**
 * Tests {@link RemoteAuthenticationProvider}.
 *
 * @author Ben Alex
 */
public class RemoteAuthenticationProviderTests {

	@Test
	public void testExceptionsGetPassedBackToCaller() {
		RemoteAuthenticationProvider provider = new RemoteAuthenticationProvider();
		provider.setRemoteAuthenticationManager(new MockRemoteAuthenticationManager(false));

		try {
			provider.authenticate(new UsernamePasswordAuthenticationToken("rod", "password"));
			fail("Should have thrown RemoteAuthenticationException");
		}
		catch (RemoteAuthenticationException expected) {

		}
	}

	@Test
	public void testGettersSetters() {
		RemoteAuthenticationProvider provider = new RemoteAuthenticationProvider();
		provider.setRemoteAuthenticationManager(new MockRemoteAuthenticationManager(true));
		assertThat(provider.getRemoteAuthenticationManager()).isNotNull();
	}

	@Test
	public void testStartupChecksAuthenticationManagerSet() throws Exception {
		RemoteAuthenticationProvider provider = new RemoteAuthenticationProvider();

		try {
			provider.afterPropertiesSet();
			fail("Should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {

		}

		provider.setRemoteAuthenticationManager(new MockRemoteAuthenticationManager(true));
		provider.afterPropertiesSet();

	}

	@Test
	public void testSuccessfulAuthenticationCreatesObject() {
		RemoteAuthenticationProvider provider = new RemoteAuthenticationProvider();
		provider.setRemoteAuthenticationManager(new MockRemoteAuthenticationManager(true));

		Authentication result = provider.authenticate(new UsernamePasswordAuthenticationToken("rod", "password"));
		assertThat(result.getPrincipal()).isEqualTo("rod");
		assertThat(result.getCredentials()).isEqualTo("password");
		assertThat(AuthorityUtils.authorityListToSet(result.getAuthorities())).contains("foo");
	}

	@Test
	public void testNullCredentialsDoesNotCauseNullPointerException() {
		RemoteAuthenticationProvider provider = new RemoteAuthenticationProvider();
		provider.setRemoteAuthenticationManager(new MockRemoteAuthenticationManager(false));

		try {
			provider.authenticate(new UsernamePasswordAuthenticationToken("rod", null));
			fail("Expected Exception");
		}
		catch (RemoteAuthenticationException success) {
		}

	}

	@Test
	public void testSupports() {
		RemoteAuthenticationProvider provider = new RemoteAuthenticationProvider();
		assertThat(provider.supports(UsernamePasswordAuthenticationToken.class)).isTrue();
	}

	private class MockRemoteAuthenticationManager implements RemoteAuthenticationManager {

		private boolean grantAccess;

		MockRemoteAuthenticationManager(boolean grantAccess) {
			this.grantAccess = grantAccess;
		}

		@Override
		public Collection<? extends GrantedAuthority> attemptAuthentication(String username, String password)
				throws RemoteAuthenticationException {
			if (this.grantAccess) {
				return AuthorityUtils.createAuthorityList("foo");
			}
			else {
				throw new RemoteAuthenticationException("as requested");
			}
		}

	}

}
