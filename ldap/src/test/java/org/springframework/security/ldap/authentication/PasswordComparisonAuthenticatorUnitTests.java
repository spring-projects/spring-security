/*
 * Copyright 2002-2025 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law.or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.ldap.authentication;

import java.util.Collections;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.ldap.core.AttributesMapper;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.LdapClient;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.ldap.query.LdapQuery;
import org.springframework.ldap.support.LdapUtils;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.ldap.search.LdapUserSearch;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Unit tests for {@link PasswordComparisonAuthenticator}.
 *
 * @author Minkuk Jo
 */
@ExtendWith(MockitoExtension.class)
class PasswordComparisonAuthenticatorUnitTests {

	@Mock
	BaseLdapPathContextSource contextSource;

	@InjectMocks
	PasswordComparisonAuthenticator authenticator;

	@Mock
	LdapClient ldapClient;

	@Mock
	LdapClient.SearchSpec searchSpec;

	@Test
	void authenticateWhenUserNotFoundThenThrowsUsernameNotFoundException() {
		this.authenticator.setUserDnPatterns(new String[] { "uid={0},ou=people" });
		this.authenticator.ldapClient = this.ldapClient;
		UsernamePasswordAuthenticationToken authentication = UsernamePasswordAuthenticationToken.unauthenticated("user",
				"password");
		given(this.ldapClient.search()).willReturn(this.searchSpec);
		given(this.searchSpec.query(any(LdapQuery.class))).willReturn(this.searchSpec);
		given(this.searchSpec.toObject(any(AttributesMapper.class))).willThrow(new EmptyResultDataAccessException(1));
		LdapUserSearch userSearch = mock(LdapUserSearch.class);
		this.authenticator.setUserSearch(userSearch);
		given(userSearch.searchForUser("user")).willReturn(null);

		assertThatExceptionOfType(UsernameNotFoundException.class)
			.isThrownBy(() -> this.authenticator.authenticate(authentication))
			.withMessage("user not found");
		verifyNoInteractions(this.contextSource);
	}


	@Test
	void authenticateWhenPasswordCompareFailsThenThrowsBadCredentialsException() {
		this.authenticator.setUserDnPatterns(new String[] { "uid={0},ou=people" });
		this.authenticator.ldapClient = this.ldapClient;
		UsernamePasswordAuthenticationToken authentication = UsernamePasswordAuthenticationToken.unauthenticated("user",
				"password");

		DirContextOperations user = mock(DirContextOperations.class);
		LdapClient.SearchSpec userSearchSpec = mock(LdapClient.SearchSpec.class);
		given(user.getDn()).willReturn(LdapUtils.newLdapName("uid=user,ou=people"));
		given(userSearchSpec.query(any(LdapQuery.class))).willReturn(userSearchSpec);
		given(userSearchSpec.toObject(any(AttributesMapper.class))).willReturn(user);

		LdapClient.SearchSpec passwordSearchSpec = mock(LdapClient.SearchSpec.class);
		given(passwordSearchSpec.query(any(LdapQuery.class))).willReturn(passwordSearchSpec);
		given(passwordSearchSpec.toList(any(AttributesMapper.class))).willReturn(Collections.emptyList());

		given(this.ldapClient.search()).willReturn(userSearchSpec, passwordSearchSpec);

		assertThatExceptionOfType(BadCredentialsException.class)
				.isThrownBy(() -> this.authenticator.authenticate(authentication));
	}
}
