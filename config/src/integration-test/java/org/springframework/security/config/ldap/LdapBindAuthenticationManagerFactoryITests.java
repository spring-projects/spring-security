/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.config.ldap;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.ldap.server.ApacheDSContainer;
import org.springframework.security.ldap.userdetails.DefaultLdapAuthoritiesPopulator;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;
import org.springframework.security.ldap.userdetails.UserDetailsContextMapper;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.Mockito.mock;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;

@ExtendWith(SpringTestContextExtension.class)
public class LdapBindAuthenticationManagerFactoryITests {

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	private MockMvc mockMvc;

	@Test
	public void authenticationManagerFactoryWhenFromContextSourceThenAuthenticates() throws Exception {
		this.spring.register(FromContextSourceConfig.class).autowire();

		this.mockMvc.perform(formLogin().user("bob").password("bobspassword"))
				.andExpect(authenticated().withUsername("bob"));
	}

	@Test
	public void ldapAuthenticationProviderCustomLdapAuthoritiesPopulator() throws Exception {
		CustomAuthoritiesPopulatorConfig.LAP = new DefaultLdapAuthoritiesPopulator(mock(LdapContextSource.class),
				null) {
			@Override
			protected Set<GrantedAuthority> getAdditionalRoles(DirContextOperations user, String username) {
				return new HashSet<>(AuthorityUtils.createAuthorityList("ROLE_EXTRA"));
			}
		};

		this.spring.register(CustomAuthoritiesPopulatorConfig.class).autowire();

		this.mockMvc.perform(formLogin().user("bob").password("bobspassword")).andExpect(
				authenticated().withAuthorities(Collections.singleton(new SimpleGrantedAuthority("ROLE_EXTRA"))));
	}

	@Test
	public void authenticationManagerFactoryWhenCustomAuthoritiesMapperThenUsed() throws Exception {
		CustomAuthoritiesMapperConfig.AUTHORITIES_MAPPER = ((authorities) -> AuthorityUtils
				.createAuthorityList("ROLE_CUSTOM"));

		this.spring.register(CustomAuthoritiesMapperConfig.class).autowire();

		this.mockMvc.perform(formLogin().user("bob").password("bobspassword")).andExpect(
				authenticated().withAuthorities(Collections.singleton(new SimpleGrantedAuthority("ROLE_CUSTOM"))));
	}

	@Test
	public void authenticationManagerFactoryWhenCustomUserDetailsContextMapperThenUsed() throws Exception {
		CustomUserDetailsContextMapperConfig.CONTEXT_MAPPER = new UserDetailsContextMapper() {
			@Override
			public UserDetails mapUserFromContext(DirContextOperations ctx, String username,
					Collection<? extends GrantedAuthority> authorities) {
				return User.withUsername("other").password("password").roles("USER").build();
			}

			@Override
			public void mapUserToContext(UserDetails user, DirContextAdapter ctx) {
			}
		};

		this.spring.register(CustomUserDetailsContextMapperConfig.class).autowire();

		this.mockMvc.perform(formLogin().user("bob").password("bobspassword"))
				.andExpect(authenticated().withUsername("other"));
	}

	@Test
	public void authenticationManagerFactoryWhenCustomUserDnPatternsThenUsed() throws Exception {
		this.spring.register(CustomUserDnPatternsConfig.class).autowire();

		this.mockMvc.perform(formLogin().user("bob").password("bobspassword"))
				.andExpect(authenticated().withUsername("bob"));
	}

	@Test
	public void authenticationManagerFactoryWhenCustomUserSearchThenUsed() throws Exception {
		this.spring.register(CustomUserSearchConfig.class).autowire();

		this.mockMvc.perform(formLogin().user("bob").password("bobspassword"))
				.andExpect(authenticated().withUsername("bob"));
	}

	@Configuration
	@EnableWebSecurity
	static class FromContextSourceConfig extends BaseLdapServerConfig {

		@Bean
		AuthenticationManager authenticationManager(BaseLdapPathContextSource contextSource) {
			LdapBindAuthenticationManagerFactory factory = new LdapBindAuthenticationManagerFactory(contextSource);
			factory.setUserDnPatterns("uid={0},ou=people");
			return factory.createAuthenticationManager();
		}

	}

	@Configuration
	@EnableWebSecurity
	static class CustomAuthoritiesMapperConfig extends BaseLdapServerConfig {

		static GrantedAuthoritiesMapper AUTHORITIES_MAPPER;

		@Bean
		AuthenticationManager authenticationManager(BaseLdapPathContextSource contextSource) {
			LdapBindAuthenticationManagerFactory factory = new LdapBindAuthenticationManagerFactory(contextSource);
			factory.setUserDnPatterns("uid={0},ou=people");
			factory.setAuthoritiesMapper(AUTHORITIES_MAPPER);
			return factory.createAuthenticationManager();
		}

	}

	@Configuration
	@EnableWebSecurity
	static class CustomAuthoritiesPopulatorConfig extends BaseLdapServerConfig {

		static LdapAuthoritiesPopulator LAP;

		@Bean
		AuthenticationManager authenticationManager(BaseLdapPathContextSource contextSource) {
			LdapBindAuthenticationManagerFactory factory = new LdapBindAuthenticationManagerFactory(contextSource);
			factory.setUserDnPatterns("uid={0},ou=people");
			factory.setLdapAuthoritiesPopulator(LAP);
			return factory.createAuthenticationManager();
		}

	}

	@Configuration
	@EnableWebSecurity
	static class CustomUserDetailsContextMapperConfig extends BaseLdapServerConfig {

		static UserDetailsContextMapper CONTEXT_MAPPER;

		@Bean
		AuthenticationManager authenticationManager(BaseLdapPathContextSource contextSource) {
			LdapBindAuthenticationManagerFactory factory = new LdapBindAuthenticationManagerFactory(contextSource);
			factory.setUserDnPatterns("uid={0},ou=people");
			factory.setUserDetailsContextMapper(CONTEXT_MAPPER);
			return factory.createAuthenticationManager();
		}

	}

	@Configuration
	@EnableWebSecurity
	static class CustomUserDnPatternsConfig extends BaseLdapServerConfig {

		@Bean
		AuthenticationManager authenticationManager(BaseLdapPathContextSource contextSource) {
			LdapBindAuthenticationManagerFactory factory = new LdapBindAuthenticationManagerFactory(contextSource);
			factory.setUserDnPatterns("uid={0},ou=people");
			return factory.createAuthenticationManager();
		}

	}

	@Configuration
	@EnableWebSecurity
	static class CustomUserSearchConfig extends BaseLdapServerConfig {

		@Bean
		AuthenticationManager authenticationManager(BaseLdapPathContextSource contextSource) {
			LdapBindAuthenticationManagerFactory factory = new LdapBindAuthenticationManagerFactory(contextSource);
			factory.setUserSearchFilter("uid={0}");
			factory.setUserSearchBase("ou=people");
			return factory.createAuthenticationManager();
		}

	}

	@Configuration
	@EnableWebSecurity
	abstract static class BaseLdapServerConfig implements DisposableBean {

		private ApacheDSContainer container;

		@Bean
		ApacheDSContainer ldapServer() throws Exception {
			this.container = new ApacheDSContainer("dc=springframework,dc=org", "classpath:/test-server.ldif");
			this.container.setPort(0);
			return this.container;
		}

		@Bean
		BaseLdapPathContextSource contextSource(ApacheDSContainer container) {
			int port = container.getLocalPort();
			return new DefaultSpringSecurityContextSource("ldap://localhost:" + port + "/dc=springframework,dc=org");
		}

		@Override
		public void destroy() {
			this.container.stop();
		}

	}

}
