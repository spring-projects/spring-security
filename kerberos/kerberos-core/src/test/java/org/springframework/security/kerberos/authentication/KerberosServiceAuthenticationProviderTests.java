/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.kerberos.authentication;

import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

/**
 * Test class for {@link KerberosServiceAuthenticationProvider}
 *
 * @author Mike Wiesner
 * @author Jeremy Stone
 * @since 1.0
 */
public class KerberosServiceAuthenticationProviderTests {

	private KerberosServiceAuthenticationProvider provider;

	private KerberosTicketValidator ticketValidator;

	private UserDetailsService userDetailsService;

	// data
	private static final byte[] TEST_TOKEN = "TestToken".getBytes();

	private static final byte[] RESPONSE_TOKEN = "ResponseToken".getBytes();

	private static final String TEST_USER = "Testuser@SPRINGSOURCE.ORG";

	private static final KerberosTicketValidation TICKET_VALIDATION = new KerberosTicketValidation(TEST_USER,
			"XXX@test.com", RESPONSE_TOKEN, null);

	private static final List<GrantedAuthority> AUTHORITY_LIST = AuthorityUtils.createAuthorityList("ROLE_ADMIN");

	private static final UserDetails USER_DETAILS = new User(TEST_USER, "empty", true, true, true, true,
			AUTHORITY_LIST);

	private static final KerberosServiceRequestToken INPUT_TOKEN = new KerberosServiceRequestToken(TEST_TOKEN);

	@BeforeEach
	public void before() {
		System.setProperty("java.security.krb5.conf", "test.com");
		System.setProperty("java.security.krb5.kdc", "kdc.test.com");
		// mocking
		this.ticketValidator = mock(KerberosTicketValidator.class);
		this.userDetailsService = mock(UserDetailsService.class);
		this.provider = new KerberosServiceAuthenticationProvider();
		this.provider.setTicketValidator(this.ticketValidator);
		this.provider.setUserDetailsService(this.userDetailsService);
	}

	@AfterEach
	public void after() {
		System.clearProperty("java.security.krb5.conf");
		System.clearProperty("java.security.krb5.kdc");
	}

	@Test
	public void testEverythingWorks() throws Exception {
		Authentication output = callProviderAndReturnUser(USER_DETAILS, INPUT_TOKEN);
		assertThat(output).isNotNull();
		assertThat(output.getName()).isEqualTo(TEST_USER);
		assertThat(output.getAuthorities()).isEqualTo(AUTHORITY_LIST);
		assertThat(output.getPrincipal()).isEqualTo(USER_DETAILS);
	}

	@Test
	public void testAuthenticationDetailsPropagation() throws Exception {
		KerberosServiceRequestToken requestToken = new KerberosServiceRequestToken(TEST_TOKEN);
		requestToken.setDetails("TestDetails");
		Authentication output = callProviderAndReturnUser(USER_DETAILS, requestToken);
		assertThat(output).isNotNull();
		assertThat(output.getDetails()).isEqualTo(requestToken.getDetails());
	}

	@Test
	public void testUserIsDisabled() throws Exception {
		assertThatExceptionOfType(DisabledException.class).isThrownBy(() -> {
			User disabledUser = new User(TEST_USER, "empty", false, true, true, true, AUTHORITY_LIST);
			callProviderAndReturnUser(disabledUser, INPUT_TOKEN);
		});
	}

	@Test
	public void testUserAccountIsExpired() throws Exception {
		assertThatExceptionOfType(AccountExpiredException.class).isThrownBy(() -> {
			User expiredUser = new User(TEST_USER, "empty", true, false, true, true, AUTHORITY_LIST);
			callProviderAndReturnUser(expiredUser, INPUT_TOKEN);
		}).isInstanceOf(AccountExpiredException.class);
	}

	@Test
	public void testUserCredentialsExpired() throws Exception {
		assertThatExceptionOfType(CredentialsExpiredException.class).isThrownBy(() -> {
			User credExpiredUser = new User(TEST_USER, "empty", true, true, false, true, AUTHORITY_LIST);
			callProviderAndReturnUser(credExpiredUser, INPUT_TOKEN);
		});
	}

	@Test
	public void testUserAccountLockedCredentialsExpired() throws Exception {
		assertThatExceptionOfType(LockedException.class).isThrownBy(() -> {
			User lockedUser = new User(TEST_USER, "empty", true, true, true, false, AUTHORITY_LIST);
			callProviderAndReturnUser(lockedUser, INPUT_TOKEN);
		});
	}

	@Test
	public void testUsernameNotFound() throws Exception {
		// stubbing
		given(this.ticketValidator.validateTicket(TEST_TOKEN)).willReturn(TICKET_VALIDATION);
		given(this.userDetailsService.loadUserByUsername(TEST_USER)).willThrow(new UsernameNotFoundException(""));

		// testing
		assertThatExceptionOfType(UsernameNotFoundException.class)
			.isThrownBy(() -> this.provider.authenticate(INPUT_TOKEN));
	}

	@Test
	public void testTicketValidationWrong() throws Exception {
		// stubbing
		given(this.ticketValidator.validateTicket(TEST_TOKEN)).willThrow(new BadCredentialsException(""));

		// testing
		assertThatExceptionOfType(BadCredentialsException.class)
			.isThrownBy(() -> this.provider.authenticate(INPUT_TOKEN));
	}

	private Authentication callProviderAndReturnUser(UserDetails userDetails, Authentication inputToken) {
		// stubbing
		given(this.ticketValidator.validateTicket(TEST_TOKEN)).willReturn(TICKET_VALIDATION);
		given(this.userDetailsService.loadUserByUsername(TEST_USER)).willReturn(userDetails);

		// testing
		return this.provider.authenticate(inputToken);
	}

}
