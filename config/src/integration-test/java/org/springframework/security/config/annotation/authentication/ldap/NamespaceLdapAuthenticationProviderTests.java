/*
 * Copyright 2002-2019 the original author or authors.
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

package org.springframework.security.config.annotation.authentication.ldap;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.security.config.annotation.authentication.ldap.NamespaceLdapAuthenticationProviderTestsConfigs.CustomAuthoritiesPopulatorConfig;
import org.springframework.security.config.annotation.authentication.ldap.NamespaceLdapAuthenticationProviderTestsConfigs.CustomLdapAuthenticationProviderConfig;
import org.springframework.security.config.annotation.authentication.ldap.NamespaceLdapAuthenticationProviderTestsConfigs.LdapAuthenticationProviderConfig;
import org.springframework.security.config.annotation.authentication.ldap.NamespaceLdapAuthenticationProviderTestsConfigs.PasswordCompareLdapConfig;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.ldap.userdetails.DefaultLdapAuthoritiesPopulator;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders;
import org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;

@ExtendWith(SpringTestContextExtension.class)
public class NamespaceLdapAuthenticationProviderTests {

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private FilterChainProxy filterChainProxy;

	@Test
	public void ldapAuthenticationProvider() throws Exception {
		this.spring.register(LdapAuthenticationProviderConfig.class).autowire();

		// @formatter:off
		SecurityMockMvcRequestBuilders.FormLoginRequestBuilder request = formLogin()
				.user("bob")
				.password("bobspassword");
		SecurityMockMvcResultMatchers.AuthenticatedMatcher user = authenticated()
				.withUsername("bob");
		// @formatter:on
		this.mockMvc.perform(request).andExpect(user);
	}

	@Test
	public void ldapAuthenticationProviderCustom() throws Exception {
		this.spring.register(CustomLdapAuthenticationProviderConfig.class).autowire();

		// @formatter:off
		SecurityMockMvcRequestBuilders.FormLoginRequestBuilder request = formLogin()
				.user("bob")
				.password("bobspassword");
		SecurityMockMvcResultMatchers.AuthenticatedMatcher user = authenticated()
				.withAuthorities(Collections.singleton(new SimpleGrantedAuthority("PREFIX_DEVELOPERS")));
		// @formatter:on
		this.mockMvc.perform(request).andExpect(user);
	}

	// SEC-2490
	@Test
	public void ldapAuthenticationProviderCustomLdapAuthoritiesPopulator() throws Exception {
		LdapContextSource contextSource = new DefaultSpringSecurityContextSource(
				"ldap://blah.example.com:789/dc=springframework,dc=org");
		CustomAuthoritiesPopulatorConfig.LAP = new DefaultLdapAuthoritiesPopulator(contextSource, null) {
			@Override
			protected Set<GrantedAuthority> getAdditionalRoles(DirContextOperations user, String username) {
				return new HashSet<>(AuthorityUtils.createAuthorityList("ROLE_EXTRA"));
			}
		};

		this.spring.register(CustomAuthoritiesPopulatorConfig.class).autowire();

		// @formatter:off
		SecurityMockMvcRequestBuilders.FormLoginRequestBuilder request = formLogin()
				.user("bob")
				.password("bobspassword");
		SecurityMockMvcResultMatchers.AuthenticatedMatcher user = authenticated()
				.withAuthorities(Collections.singleton(new SimpleGrantedAuthority("ROLE_EXTRA")));
		// @formatter:on
		this.mockMvc.perform(request).andExpect(user);
	}

	@Test
	public void ldapAuthenticationProviderPasswordCompare() throws Exception {
		this.spring.register(PasswordCompareLdapConfig.class).autowire();

		// @formatter:off
		SecurityMockMvcRequestBuilders.FormLoginRequestBuilder request = formLogin()
				.user("bcrypt")
				.password("password");
		SecurityMockMvcResultMatchers.AuthenticatedMatcher user = authenticated().withUsername("bcrypt");
		// @formatter:on
		this.mockMvc.perform(request).andExpect(user);
	}

}
