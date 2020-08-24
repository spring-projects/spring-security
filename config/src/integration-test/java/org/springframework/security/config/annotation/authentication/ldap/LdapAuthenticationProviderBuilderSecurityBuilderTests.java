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

import java.io.IOException;
import java.net.ServerSocket;
import java.util.Collections;
import java.util.List;

import javax.naming.directory.SearchControls;

import org.junit.Rule;
import org.junit.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.EnableGlobalAuthentication;
import org.springframework.security.config.annotation.configuration.ObjectPostProcessorConfiguration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider;
import org.springframework.security.ldap.server.ApacheDSContainer;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;

public class LdapAuthenticationProviderBuilderSecurityBuilderTests {

	static Integer port;

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private AuthenticationManager authenticationManager;

	@Test
	public void defaultConfiguration() {
		this.spring.register(DefaultLdapConfig.class).autowire();
		LdapAuthenticationProvider provider = ldapProvider();

		LdapAuthoritiesPopulator authoritiesPopulator = getAuthoritiesPopulator(provider);
		assertThat(authoritiesPopulator).hasFieldOrPropertyWithValue("groupRoleAttribute", "cn");
		assertThat(authoritiesPopulator).hasFieldOrPropertyWithValue("groupSearchBase", "");
		assertThat(authoritiesPopulator).hasFieldOrPropertyWithValue("groupSearchFilter", "(uniqueMember={0})");
		assertThat(authoritiesPopulator).extracting("searchControls").hasFieldOrPropertyWithValue("searchScope",
				SearchControls.ONELEVEL_SCOPE);
		assertThat(ReflectionTestUtils.getField(getAuthoritiesMapper(provider), "prefix")).isEqualTo("ROLE_");
	}

	@Test
	public void groupRolesCustom() {
		this.spring.register(GroupRolesConfig.class).autowire();
		LdapAuthenticationProvider provider = ldapProvider();

		assertThat(ReflectionTestUtils.getField(getAuthoritiesPopulator(provider), "groupRoleAttribute"))
				.isEqualTo("group");
	}

	@Test
	public void groupSearchCustom() {
		this.spring.register(GroupSearchConfig.class).autowire();
		LdapAuthenticationProvider provider = ldapProvider();

		assertThat(ReflectionTestUtils.getField(getAuthoritiesPopulator(provider), "groupSearchFilter"))
				.isEqualTo("ou=groupName");
	}

	@Test
	public void groupSubtreeSearchCustom() {
		this.spring.register(GroupSubtreeSearchConfig.class).autowire();
		LdapAuthenticationProvider provider = ldapProvider();

		assertThat(ReflectionTestUtils.getField(getAuthoritiesPopulator(provider), "searchControls"))
				.extracting("searchScope").isEqualTo(SearchControls.SUBTREE_SCOPE);
	}

	@Test
	public void rolePrefixCustom() {
		this.spring.register(RolePrefixConfig.class).autowire();
		LdapAuthenticationProvider provider = ldapProvider();

		assertThat(ReflectionTestUtils.getField(getAuthoritiesMapper(provider), "prefix")).isEqualTo("role_");
	}

	@Test
	public void bindAuthentication() throws Exception {
		this.spring.register(BindAuthenticationConfig.class).autowire();

		this.mockMvc.perform(formLogin().user("bob").password("bobspassword"))
				.andExpect(authenticated().withUsername("bob")
						.withAuthorities(Collections.singleton(new SimpleGrantedAuthority("ROLE_DEVELOPERS"))));
	}

	// SEC-2472
	@Test
	public void canUseCryptoPasswordEncoder() throws Exception {
		this.spring.register(PasswordEncoderConfig.class).autowire();

		this.mockMvc.perform(formLogin().user("bcrypt").password("password"))
				.andExpect(authenticated().withUsername("bcrypt")
						.withAuthorities(Collections.singleton(new SimpleGrantedAuthority("ROLE_DEVELOPERS"))));
	}

	private LdapAuthenticationProvider ldapProvider() {
		return ((List<LdapAuthenticationProvider>) ReflectionTestUtils.getField(this.authenticationManager,
				"providers")).get(0);
	}

	private LdapAuthoritiesPopulator getAuthoritiesPopulator(LdapAuthenticationProvider provider) {
		return (LdapAuthoritiesPopulator) ReflectionTestUtils.getField(provider, "authoritiesPopulator");
	}

	private GrantedAuthoritiesMapper getAuthoritiesMapper(LdapAuthenticationProvider provider) {
		return (GrantedAuthoritiesMapper) ReflectionTestUtils.getField(provider, "authoritiesMapper");
	}

	static int getPort() throws IOException {
		if (port == null) {
			ServerSocket socket = new ServerSocket(0);
			port = socket.getLocalPort();
			socket.close();
		}
		return port;
	}

	@EnableWebSecurity
	static class DefaultLdapConfig extends BaseLdapProviderConfig {

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
				.ldapAuthentication()
					.contextSource(contextSource())
					.userDnPatterns("uid={0},ou=people");
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class GroupRolesConfig extends BaseLdapProviderConfig {

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
				.ldapAuthentication()
					.contextSource(contextSource())
					.userDnPatterns("uid={0},ou=people")
					.groupRoleAttribute("group");
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class GroupSearchConfig extends BaseLdapProviderConfig {

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
				.ldapAuthentication()
					.contextSource(contextSource())
					.userDnPatterns("uid={0},ou=people")
					.groupSearchFilter("ou=groupName");
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class GroupSubtreeSearchConfig extends BaseLdapProviderConfig {

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
				.ldapAuthentication()
					.contextSource(contextSource())
					.userDnPatterns("uid={0},ou=people")
					.groupSearchFilter("ou=groupName")
					.groupSearchSubtree(true);
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class RolePrefixConfig extends BaseLdapProviderConfig {

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
				.ldapAuthentication()
					.contextSource(contextSource())
					.userDnPatterns("uid={0},ou=people")
					.rolePrefix("role_");
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class BindAuthenticationConfig extends BaseLdapServerConfig {

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
				.ldapAuthentication()
					.contextSource(contextSource())
					.groupSearchBase("ou=groups")
					.groupSearchFilter("(member={0})")
					.userDnPatterns("uid={0},ou=people");
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class PasswordEncoderConfig extends BaseLdapServerConfig {

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
				.ldapAuthentication()
					.contextSource(contextSource())
					.passwordEncoder(new BCryptPasswordEncoder())
					.groupSearchBase("ou=groups")
					.groupSearchFilter("(member={0})")
					.userDnPatterns("uid={0},ou=people");
			// @formatter:on
		}

	}

	@EnableWebSecurity
	abstract static class BaseLdapServerConfig extends BaseLdapProviderConfig {

		@Bean
		ApacheDSContainer ldapServer() throws Exception {
			ApacheDSContainer apacheDSContainer = new ApacheDSContainer("dc=springframework,dc=org",
					"classpath:/test-server.ldif");
			apacheDSContainer.setPort(getPort());
			return apacheDSContainer;
		}

	}

	@EnableWebSecurity
	@EnableGlobalAuthentication
	@Import(ObjectPostProcessorConfiguration.class)
	abstract static class BaseLdapProviderConfig extends WebSecurityConfigurerAdapter {

		@Bean
		BaseLdapPathContextSource contextSource() throws Exception {
			DefaultSpringSecurityContextSource contextSource = new DefaultSpringSecurityContextSource(
					"ldap://127.0.0.1:" + getPort() + "/dc=springframework,dc=org");
			contextSource.setUserDn("uid=admin,ou=system");
			contextSource.setPassword("secret");
			contextSource.afterPropertiesSet();
			return contextSource;
		}

		@Bean
		AuthenticationManager authenticationManager(AuthenticationManagerBuilder auth) throws Exception {
			configure(auth);
			return auth.build();
		}

		@Override
		protected abstract void configure(AuthenticationManagerBuilder auth) throws Exception;

	}

}
