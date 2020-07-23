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

package org.springframework.security.openid;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

import org.junit.Test;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsByNameServiceWrapper;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * Tests {@link OpenIDAuthenticationProvider}
 *
 * @deprecated The OpenID 1.0 and 2.0 protocols have been deprecated and users are
 * <a href="https://openid.net/specs/openid-connect-migration-1_0.html">encouraged to
 * migrate</a> to <a href="https://openid.net/connect/">OpenID Connect</a>, which is
 * supported by <code>spring-security-oauth2</code>.
 * @author Robin Bramley, Opsera Ltd
 */
public class OpenIDAuthenticationProviderTests {

	private static final String USERNAME = "user.acegiopenid.com";

	/*
	 * Test method for
	 * 'org.springframework.security.authentication.openid.OpenIDAuthenticationProvider.
	 * authenticate(Authentication)'
	 */
	@Test
	public void testAuthenticateCancel() {
		OpenIDAuthenticationProvider provider = new OpenIDAuthenticationProvider();
		provider.setUserDetailsService(new MockUserDetailsService());
		provider.setAuthoritiesMapper(new NullAuthoritiesMapper());

		Authentication preAuth = new OpenIDAuthenticationToken(OpenIDAuthenticationStatus.CANCELLED, USERNAME, "",
				null);

		assertThat(preAuth.isAuthenticated()).isFalse();

		try {
			provider.authenticate(preAuth);
			fail("Should throw an AuthenticationException");
		}
		catch (AuthenticationCancelledException expected) {
			assertThat(expected.getMessage()).isEqualTo("Log in cancelled");
		}
	}

	/*
	 * Test method for
	 * 'org.springframework.security.authentication.openid.OpenIDAuthenticationProvider.
	 * authenticate(Authentication)'
	 */
	@Test
	public void testAuthenticateError() {
		OpenIDAuthenticationProvider provider = new OpenIDAuthenticationProvider();
		provider.setUserDetailsService(new MockUserDetailsService());

		Authentication preAuth = new OpenIDAuthenticationToken(OpenIDAuthenticationStatus.ERROR, USERNAME, "", null);

		assertThat(preAuth.isAuthenticated()).isFalse();

		try {
			provider.authenticate(preAuth);
			fail("Should throw an AuthenticationException");
		}
		catch (AuthenticationServiceException expected) {
			assertThat(expected.getMessage()).isEqualTo("Error message from server: ");
		}
	}

	/*
	 * Test method for
	 * 'org.springframework.security.authentication.openid.OpenIDAuthenticationProvider.
	 * authenticate(Authentication)'
	 */
	@Test
	public void testAuthenticateFailure() {
		OpenIDAuthenticationProvider provider = new OpenIDAuthenticationProvider();
		provider.setAuthenticationUserDetailsService(
				new UserDetailsByNameServiceWrapper<>(new MockUserDetailsService()));

		Authentication preAuth = new OpenIDAuthenticationToken(OpenIDAuthenticationStatus.FAILURE, USERNAME, "", null);

		assertThat(preAuth.isAuthenticated()).isFalse();

		try {
			provider.authenticate(preAuth);
			fail("Should throw an AuthenticationException");
		}
		catch (BadCredentialsException expected) {
			assertThat("Log in failed - identity could not be verified").isEqualTo(expected.getMessage());
		}
	}

	/*
	 * Test method for
	 * 'org.springframework.security.authentication.openid.OpenIDAuthenticationProvider.
	 * authenticate(Authentication)'
	 */
	@Test
	public void testAuthenticateSetupNeeded() {
		OpenIDAuthenticationProvider provider = new OpenIDAuthenticationProvider();
		provider.setUserDetailsService(new MockUserDetailsService());

		Authentication preAuth = new OpenIDAuthenticationToken(OpenIDAuthenticationStatus.SETUP_NEEDED, USERNAME, "",
				null);

		assertThat(preAuth.isAuthenticated()).isFalse();

		try {
			provider.authenticate(preAuth);
			fail("Should throw an AuthenticationException");
		}
		catch (AuthenticationServiceException expected) {
			assertThat("The server responded setup was needed, which shouldn't happen")
					.isEqualTo(expected.getMessage());
		}
	}

	/*
	 * Test method for
	 * 'org.springframework.security.authentication.openid.OpenIDAuthenticationProvider.
	 * authenticate(Authentication)'
	 */
	@Test
	public void testAuthenticateSuccess() {
		OpenIDAuthenticationProvider provider = new OpenIDAuthenticationProvider();
		provider.setUserDetailsService(new MockUserDetailsService());

		Authentication preAuth = new OpenIDAuthenticationToken(OpenIDAuthenticationStatus.SUCCESS, USERNAME, "", null);

		assertThat(preAuth.isAuthenticated()).isFalse();

		Authentication postAuth = provider.authenticate(preAuth);

		assertThat(postAuth).isNotNull();
		assertThat(postAuth instanceof OpenIDAuthenticationToken).isTrue();
		assertThat(postAuth.isAuthenticated()).isTrue();
		assertThat(postAuth.getPrincipal()).isNotNull();
		assertThat(postAuth.getPrincipal() instanceof UserDetails).isTrue();
		assertThat(postAuth.getAuthorities()).isNotNull();
		assertThat(postAuth.getAuthorities().size() > 0).isTrue();
		assertThat(((OpenIDAuthenticationToken) postAuth).getStatus() == OpenIDAuthenticationStatus.SUCCESS).isTrue();
		assertThat(((OpenIDAuthenticationToken) postAuth).getMessage() == null).isTrue();
	}

	@Test
	public void testDetectsMissingAuthoritiesPopulator() throws Exception {
		OpenIDAuthenticationProvider provider = new OpenIDAuthenticationProvider();

		try {
			provider.afterPropertiesSet();
			fail("Should have thrown Exception");
		}
		catch (IllegalArgumentException expected) {
			// ignored
		}
	}

	/*
	 * Test method for
	 * 'org.springframework.security.authentication.openid.OpenIDAuthenticationProvider.
	 * supports(Class)'
	 */
	@Test
	public void testDoesntSupport() {
		OpenIDAuthenticationProvider provider = new OpenIDAuthenticationProvider();
		provider.setUserDetailsService(new MockUserDetailsService());

		assertThat(provider.supports(UsernamePasswordAuthenticationToken.class)).isFalse();
	}

	/*
	 * Test method for
	 * 'org.springframework.security.authentication.openid.OpenIDAuthenticationProvider.
	 * authenticate(Authentication)'
	 */
	@Test
	public void testIgnoresUserPassAuthToken() {
		OpenIDAuthenticationProvider provider = new OpenIDAuthenticationProvider();
		provider.setUserDetailsService(new MockUserDetailsService());

		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(USERNAME, "password");
		assertThat(provider.authenticate(token)).isNull();
	}

	/*
	 * Test method for
	 * 'org.springframework.security.authentication.openid.OpenIDAuthenticationProvider.
	 * supports(Class)'
	 */
	@Test
	public void testSupports() {
		OpenIDAuthenticationProvider provider = new OpenIDAuthenticationProvider();
		provider.setUserDetailsService(new MockUserDetailsService());

		assertThat(provider.supports(OpenIDAuthenticationToken.class)).isTrue();
	}

	@Test
	public void testValidation() throws Exception {
		OpenIDAuthenticationProvider provider = new OpenIDAuthenticationProvider();
		try {
			provider.afterPropertiesSet();
			fail("IllegalArgumentException expected, ssoAuthoritiesPopulator is null");
		}
		catch (IllegalArgumentException e) {
			// expected
		}

		provider = new OpenIDAuthenticationProvider();
		provider.setUserDetailsService(new MockUserDetailsService());
		provider.afterPropertiesSet();
	}

	static class MockUserDetailsService implements UserDetailsService {

		public UserDetails loadUserByUsername(String ssoUserId) throws AuthenticationException {
			return new User(ssoUserId, "password", true, true, true, true,
					AuthorityUtils.createAuthorityList("ROLE_A", "ROLE_B"));
		}

	}

}
