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

package org.springframework.security.ldap.authentication;

import java.util.Collection;

import org.junit.jupiter.api.Test;

import org.springframework.ldap.CommunicationException;
import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.support.LdapNameBuilder;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;
import org.springframework.security.ldap.userdetails.LdapUserDetailsMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

/**
 * Tests {@link LdapAuthenticationProvider}.
 *
 * @author Luke Taylor
 * @author Rob Winch
 * @author Eddú Meléndez
 */
public class LdapAuthenticationProviderTests {

	@Test
	public void testSupportsUsernamePasswordAuthenticationToken() {
		LdapAuthenticationProvider ldapProvider = new LdapAuthenticationProvider(new MockAuthenticator(),
				new MockAuthoritiesPopulator());
		assertThat(ldapProvider.supports(UsernamePasswordAuthenticationToken.class)).isTrue();
	}

	@Test
	public void testDefaultMapperIsSet() {
		LdapAuthenticationProvider ldapProvider = new LdapAuthenticationProvider(new MockAuthenticator(),
				new MockAuthoritiesPopulator());
		assertThat(ldapProvider.getUserDetailsContextMapper() instanceof LdapUserDetailsMapper).isTrue();
	}

	@Test
	public void testEmptyOrNullUserNameThrowsException() {
		LdapAuthenticationProvider ldapProvider = new LdapAuthenticationProvider(new MockAuthenticator(),
				new MockAuthoritiesPopulator());
		assertThatExceptionOfType(BadCredentialsException.class).isThrownBy(
				() -> ldapProvider.authenticate(UsernamePasswordAuthenticationToken.unauthenticated(null, "password")));
		assertThatExceptionOfType(BadCredentialsException.class).isThrownBy(() -> ldapProvider
			.authenticate(UsernamePasswordAuthenticationToken.unauthenticated("", "bobspassword")));
	}

	@Test
	public void usernameNotFoundExceptionIsHiddenByDefault() {
		final LdapAuthenticator authenticator = mock(LdapAuthenticator.class);
		final UsernamePasswordAuthenticationToken joe = UsernamePasswordAuthenticationToken.unauthenticated("joe",
				"password");
		given(authenticator.authenticate(joe)).willThrow(new UsernameNotFoundException("nobody"));
		LdapAuthenticationProvider provider = new LdapAuthenticationProvider(authenticator);
		assertThatExceptionOfType(BadCredentialsException.class).isThrownBy(() -> provider.authenticate(joe));
	}

	@Test
	public void usernameNotFoundExceptionIsNotHiddenIfConfigured() {
		final LdapAuthenticator authenticator = mock(LdapAuthenticator.class);
		final UsernamePasswordAuthenticationToken joe = UsernamePasswordAuthenticationToken.unauthenticated("joe",
				"password");
		given(authenticator.authenticate(joe)).willThrow(new UsernameNotFoundException("nobody"));
		LdapAuthenticationProvider provider = new LdapAuthenticationProvider(authenticator);
		provider.setHideUserNotFoundExceptions(false);
		assertThatExceptionOfType(UsernameNotFoundException.class).isThrownBy(() -> provider.authenticate(joe));
	}

	@Test
	public void normalUsage() {
		MockAuthoritiesPopulator populator = new MockAuthoritiesPopulator();
		LdapAuthenticationProvider ldapProvider = new LdapAuthenticationProvider(new MockAuthenticator(), populator);
		LdapUserDetailsMapper userMapper = new LdapUserDetailsMapper();
		userMapper.setRoleAttributes(new String[] { "ou" });
		ldapProvider.setUserDetailsContextMapper(userMapper);
		assertThat(ldapProvider.getAuthoritiesPopulator()).isNotNull();
		UsernamePasswordAuthenticationToken authRequest = UsernamePasswordAuthenticationToken.unauthenticated("ben",
				"benspassword");
		Object authDetails = new Object();
		authRequest.setDetails(authDetails);
		Authentication authResult = ldapProvider.authenticate(authRequest);
		assertThat(authResult.getCredentials()).isEqualTo("benspassword");
		assertThat(authResult.getDetails()).isSameAs(authDetails);
		UserDetails user = (UserDetails) authResult.getPrincipal();
		assertThat(user.getAuthorities()).hasSize(2);
		assertThat(user.getPassword()).isEqualTo("{SHA}nFCebWjxfaLbHHG1Qk5UU4trbvQ=");
		assertThat(user.getUsername()).isEqualTo("ben");
		assertThat(populator.getRequestedUsername()).isEqualTo("ben");
		assertThat(AuthorityUtils.authorityListToSet(user.getAuthorities())).contains("ROLE_FROM_ENTRY");
		assertThat(AuthorityUtils.authorityListToSet(user.getAuthorities())).contains("ROLE_FROM_POPULATOR");
	}

	@Test
	public void passwordIsSetFromUserDataIfUseAuthenticationRequestCredentialsIsFalse() {
		LdapAuthenticationProvider ldapProvider = new LdapAuthenticationProvider(new MockAuthenticator(),
				new MockAuthoritiesPopulator());
		ldapProvider.setUseAuthenticationRequestCredentials(false);
		UsernamePasswordAuthenticationToken authRequest = UsernamePasswordAuthenticationToken.unauthenticated("ben",
				"benspassword");
		Authentication authResult = ldapProvider.authenticate(authRequest);
		assertThat(authResult.getCredentials()).isEqualTo("{SHA}nFCebWjxfaLbHHG1Qk5UU4trbvQ=");
	}

	@Test
	public void useWithNullAuthoritiesPopulatorReturnsCorrectRole() {
		LdapAuthenticationProvider ldapProvider = new LdapAuthenticationProvider(new MockAuthenticator());
		LdapUserDetailsMapper userMapper = new LdapUserDetailsMapper();
		userMapper.setRoleAttributes(new String[] { "ou" });
		ldapProvider.setUserDetailsContextMapper(userMapper);
		UsernamePasswordAuthenticationToken authRequest = UsernamePasswordAuthenticationToken.unauthenticated("ben",
				"benspassword");
		UserDetails user = (UserDetails) ldapProvider.authenticate(authRequest).getPrincipal();
		assertThat(user.getAuthorities()).hasSize(1);
		assertThat(AuthorityUtils.authorityListToSet(user.getAuthorities())).contains("ROLE_FROM_ENTRY");
	}

	@Test
	public void authenticateWithNamingException() {
		UsernamePasswordAuthenticationToken authRequest = UsernamePasswordAuthenticationToken.unauthenticated("ben",
				"benspassword");
		LdapAuthenticator mockAuthenticator = mock(LdapAuthenticator.class);
		CommunicationException expectedCause = new CommunicationException(new javax.naming.CommunicationException());
		given(mockAuthenticator.authenticate(authRequest)).willThrow(expectedCause);
		LdapAuthenticationProvider ldapProvider = new LdapAuthenticationProvider(mockAuthenticator);
		assertThatExceptionOfType(InternalAuthenticationServiceException.class)
			.isThrownBy(() -> ldapProvider.authenticate(authRequest))
			.havingCause()
			.isSameAs(expectedCause);
	}

	class MockAuthenticator implements LdapAuthenticator {

		@Override
		public DirContextOperations authenticate(Authentication authentication) {
			DirContextAdapter ctx = new DirContextAdapter();
			ctx.setAttributeValue("ou", "FROM_ENTRY");
			String username = authentication.getName();
			String password = (String) authentication.getCredentials();
			if (username.equals("ben") && password.equals("benspassword")) {
				ctx.setDn(LdapNameBuilder.newInstance("cn=jen,ou=people,dc=springframework,dc=org").build());
				ctx.setAttributeValue("userPassword", "{SHA}nFCebWjxfaLbHHG1Qk5UU4trbvQ=");
				return ctx;
			}
			else if (username.equals("jen") && password.equals("")) {
				ctx.setDn(LdapNameBuilder.newInstance("cn=jen,ou=people,dc=springframework,dc=org").build());
				return ctx;
			}
			throw new BadCredentialsException("Authentication failed.");
		}

	}

	class MockAuthoritiesPopulator implements LdapAuthoritiesPopulator {

		String username;

		@Override
		public Collection<GrantedAuthority> getGrantedAuthorities(DirContextOperations userCtx, String username) {
			this.username = username;
			return AuthorityUtils.createAuthorityList("ROLE_FROM_POPULATOR");
		}

		String getRequestedUsername() {
			return this.username;
		}

	}

}
