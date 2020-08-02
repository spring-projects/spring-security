/*
 * Copyright 2002-2016 the original author or authors.
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

package org.springframework.security.ldap;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import org.springframework.ldap.core.AuthenticationSource;
import org.springframework.ldap.core.DistinguishedName;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.ldap.authentication.SpringSecurityAuthenticationSource;
import org.springframework.security.ldap.userdetails.LdapUserDetailsImpl;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Luke Taylor
 */
public class SpringSecurityAuthenticationSourceTests {

	@Before
	@After
	public void clearContext() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void principalAndCredentialsAreEmptyWithNoAuthentication() {
		AuthenticationSource source = new SpringSecurityAuthenticationSource();
		assertThat(source.getPrincipal()).isEqualTo("");
		assertThat(source.getCredentials()).isEqualTo("");
	}

	@Test
	public void principalIsEmptyForAnonymousUser() {
		AuthenticationSource source = new SpringSecurityAuthenticationSource();
		SecurityContextHolder.getContext().setAuthentication(
				new AnonymousAuthenticationToken("key", "anonUser", AuthorityUtils.createAuthorityList("ignored")));
		assertThat(source.getPrincipal()).isEqualTo("");
	}

	@Test(expected = IllegalArgumentException.class)
	public void getPrincipalRejectsNonLdapUserDetailsObject() {
		AuthenticationSource source = new SpringSecurityAuthenticationSource();
		SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken(new Object(), "password"));
		source.getPrincipal();
	}

	@Test
	public void expectedCredentialsAreReturned() {
		AuthenticationSource source = new SpringSecurityAuthenticationSource();
		SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken(new Object(), "password"));
		assertThat(source.getCredentials()).isEqualTo("password");
	}

	@Test
	public void expectedPrincipalIsReturned() {
		LdapUserDetailsImpl.Essence user = new LdapUserDetailsImpl.Essence();
		user.setUsername("joe");
		user.setDn(new DistinguishedName("uid=joe,ou=users"));
		AuthenticationSource source = new SpringSecurityAuthenticationSource();
		SecurityContextHolder.getContext()
				.setAuthentication(new TestingAuthenticationToken(user.createUserDetails(), null));
		assertThat(source.getPrincipal()).isEqualTo("uid=joe,ou=users");
	}

}
