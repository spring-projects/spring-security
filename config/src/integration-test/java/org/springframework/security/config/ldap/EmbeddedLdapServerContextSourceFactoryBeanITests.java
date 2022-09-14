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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.UnsatisfiedDependencyException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;

@ExtendWith(SpringTestContextExtension.class)
public class EmbeddedLdapServerContextSourceFactoryBeanITests {

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	private MockMvc mockMvc;

	@Test
	public void contextSourceFactoryBeanWhenEmbeddedServerThenAuthenticates() throws Exception {
		this.spring.register(FromEmbeddedLdapServerConfig.class).autowire();

		this.mockMvc.perform(formLogin().user("bob").password("bobspassword"))
				.andExpect(authenticated().withUsername("bob"));
	}

	@Test
	public void contextSourceFactoryBeanWhenPortZeroThenAuthenticates() throws Exception {
		this.spring.register(PortZeroConfig.class).autowire();

		this.mockMvc.perform(formLogin().user("bob").password("bobspassword"))
				.andExpect(authenticated().withUsername("bob"));
	}

	@Test
	public void contextSourceFactoryBeanWhenCustomLdifAndRootThenAuthenticates() throws Exception {
		this.spring.register(CustomLdifAndRootConfig.class).autowire();

		this.mockMvc.perform(formLogin().user("pg").password("password")).andExpect(authenticated().withUsername("pg"));
	}

	@Test
	public void contextSourceFactoryBeanWhenCustomManagerDnThenAuthenticates() throws Exception {
		this.spring.register(CustomManagerDnConfig.class).autowire();

		this.mockMvc.perform(formLogin().user("bob").password("bobspassword"))
				.andExpect(authenticated().withUsername("bob"));
	}

	@Test
	public void contextSourceFactoryBeanWhenManagerDnAndNoPasswordThenException() {
		assertThatExceptionOfType(UnsatisfiedDependencyException.class)
				.isThrownBy(() -> this.spring.register(CustomManagerDnNoPasswordConfig.class).autowire())
				.havingRootCause().isInstanceOf(IllegalStateException.class)
				.withMessageContaining("managerPassword is required if managerDn is supplied");
	}

	@Configuration
	@EnableWebSecurity
	static class FromEmbeddedLdapServerConfig {

		@Bean
		EmbeddedLdapServerContextSourceFactoryBean contextSourceFactoryBean() {
			return EmbeddedLdapServerContextSourceFactoryBean.fromEmbeddedLdapServer();
		}

		@Bean
		AuthenticationManager authenticationManager(LdapContextSource contextSource) {
			LdapBindAuthenticationManagerFactory factory = new LdapBindAuthenticationManagerFactory(contextSource);
			factory.setUserDnPatterns("uid={0},ou=people");
			return factory.createAuthenticationManager();
		}

	}

	@Configuration
	@EnableWebSecurity
	static class PortZeroConfig {

		@Bean
		EmbeddedLdapServerContextSourceFactoryBean contextSourceFactoryBean() {
			EmbeddedLdapServerContextSourceFactoryBean factoryBean = EmbeddedLdapServerContextSourceFactoryBean
					.fromEmbeddedLdapServer();
			factoryBean.setPort(0);
			return factoryBean;
		}

		@Bean
		AuthenticationManager authenticationManager(LdapContextSource contextSource) {
			LdapBindAuthenticationManagerFactory factory = new LdapBindAuthenticationManagerFactory(contextSource);
			factory.setUserDnPatterns("uid={0},ou=people");
			return factory.createAuthenticationManager();
		}

	}

	@Configuration
	@EnableWebSecurity
	static class CustomLdifAndRootConfig {

		@Bean
		EmbeddedLdapServerContextSourceFactoryBean contextSourceFactoryBean() {
			EmbeddedLdapServerContextSourceFactoryBean factoryBean = EmbeddedLdapServerContextSourceFactoryBean
					.fromEmbeddedLdapServer();
			factoryBean.setLdif("classpath*:test-server2.xldif");
			factoryBean.setRoot("dc=monkeymachine,dc=co,dc=uk");
			return factoryBean;
		}

		@Bean
		AuthenticationManager authenticationManager(LdapContextSource contextSource) {
			LdapBindAuthenticationManagerFactory factory = new LdapBindAuthenticationManagerFactory(contextSource);
			factory.setUserDnPatterns("uid={0},ou=gorillas");
			return factory.createAuthenticationManager();
		}

	}

	@Configuration
	@EnableWebSecurity
	static class CustomManagerDnConfig {

		@Bean
		EmbeddedLdapServerContextSourceFactoryBean contextSourceFactoryBean() {
			EmbeddedLdapServerContextSourceFactoryBean factoryBean = EmbeddedLdapServerContextSourceFactoryBean
					.fromEmbeddedLdapServer();
			factoryBean.setManagerDn("uid=admin,ou=system");
			factoryBean.setManagerPassword("secret");
			return factoryBean;
		}

		@Bean
		AuthenticationManager authenticationManager(LdapContextSource contextSource) {
			LdapPasswordComparisonAuthenticationManagerFactory factory = new LdapPasswordComparisonAuthenticationManagerFactory(
					contextSource, NoOpPasswordEncoder.getInstance());
			factory.setUserDnPatterns("uid={0},ou=people");
			return factory.createAuthenticationManager();
		}

	}

	@Configuration
	@EnableWebSecurity
	static class CustomManagerDnNoPasswordConfig {

		@Bean
		EmbeddedLdapServerContextSourceFactoryBean contextSourceFactoryBean() {
			EmbeddedLdapServerContextSourceFactoryBean factoryBean = EmbeddedLdapServerContextSourceFactoryBean
					.fromEmbeddedLdapServer();
			factoryBean.setManagerDn("uid=admin,ou=system");
			return factoryBean;
		}

		@Bean
		AuthenticationManager authenticationManager(LdapContextSource contextSource) {
			LdapPasswordComparisonAuthenticationManagerFactory factory = new LdapPasswordComparisonAuthenticationManagerFactory(
					contextSource, NoOpPasswordEncoder.getInstance());
			factory.setUserDnPatterns("uid={0},ou=people");
			return factory.createAuthenticationManager();
		}

	}

}
