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

import org.junit.Rule;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.servlet.MockMvc;

import static java.util.Collections.singleton;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;

public class LdapAuthenticationProviderConfigurerTests {
	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	private MockMvc mockMvc;

	@Test
	public void authenticationManagerSupportMultipleDefaultLdapContextsWithPortsDynamicallyAllocated() throws Exception {
		this.spring.register(MultiLdapAuthenticationProvidersConfig.class).autowire();

		this.mockMvc.perform(formLogin().user("bob").password("bobspassword"))
				.andExpect(authenticated().withUsername("bob"));
	}

	@Test
	public void authenticationManagerSupportMultipleLdapContextWithDefaultRolePrefix() throws Exception {
		this.spring.register(MultiLdapAuthenticationProvidersConfig.class).autowire();

		this.mockMvc.perform(formLogin().user("bob").password("bobspassword"))
				.andExpect(authenticated().withUsername("bob").withAuthorities(singleton(new SimpleGrantedAuthority("ROLE_DEVELOPERS"))));
	}

	@Test
	public void authenticationManagerSupportMultipleLdapContextWithCustomRolePrefix() throws Exception {
		this.spring.register(MultiLdapWithCustomRolePrefixAuthenticationProvidersConfig.class).autowire();

		this.mockMvc.perform(formLogin().user("bob").password("bobspassword"))
				.andExpect(authenticated().withUsername("bob").withAuthorities(singleton(new SimpleGrantedAuthority("ROL_DEVELOPERS"))));
	}

	@EnableWebSecurity
	static class MultiLdapAuthenticationProvidersConfig extends WebSecurityConfigurerAdapter {
		// @formatter:off
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			auth
				.ldapAuthentication()
					.groupSearchBase("ou=groups")
					.groupSearchFilter("(member={0})")
					.userDnPatterns("uid={0},ou=people")
					.and()
				.ldapAuthentication()
					.groupSearchBase("ou=groups")
					.groupSearchFilter("(member={0})")
					.userDnPatterns("uid={0},ou=people");
		}
		// @formatter:on
	}

	@EnableWebSecurity
	static class MultiLdapWithCustomRolePrefixAuthenticationProvidersConfig extends WebSecurityConfigurerAdapter {
		// @formatter:off
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			auth
				.ldapAuthentication()
					.groupSearchBase("ou=groups")
					.groupSearchFilter("(member={0})")
					.userDnPatterns("uid={0},ou=people")
					.rolePrefix("ROL_")
					.and()
				.ldapAuthentication()
					.groupSearchBase("ou=groups")
					.groupSearchFilter("(member={0})")
					.userDnPatterns("uid={0},ou=people")
					.rolePrefix("RUOLO_");
		}
		// @formatter:on
	}
}
