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

import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.ldap.server.ApacheDSContainer;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;

@ExtendWith(SpringTestContextExtension.class)
public class LdapPasswordComparisonAuthenticationManagerFactoryITests {

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	private MockMvc mockMvc;

	@Test
	public void authenticationManagerFactoryWhenCustomPasswordEncoderThenUsed() throws Exception {
		this.spring.register(CustomPasswordEncoderConfig.class).autowire();

		this.mockMvc.perform(formLogin().user("bcrypt").password("password"))
				.andExpect(authenticated().withUsername("bcrypt"));
	}

	@Test
	public void authenticationManagerFactoryWhenCustomPasswordAttributeThenUsed() throws Exception {
		this.spring.register(CustomPasswordAttributeConfig.class).autowire();

		this.mockMvc.perform(formLogin().user("bob").password("bob")).andExpect(authenticated().withUsername("bob"));
	}

	@Configuration
	@EnableWebSecurity
	static class CustomPasswordEncoderConfig extends BaseLdapServerConfig {

		@Bean
		AuthenticationManager authenticationManager(BaseLdapPathContextSource contextSource) {
			LdapPasswordComparisonAuthenticationManagerFactory factory = new LdapPasswordComparisonAuthenticationManagerFactory(
					contextSource, new BCryptPasswordEncoder());
			factory.setUserDnPatterns("uid={0},ou=people");
			return factory.createAuthenticationManager();
		}

	}

	@Configuration
	@EnableWebSecurity
	static class CustomPasswordAttributeConfig extends BaseLdapServerConfig {

		@Bean
		AuthenticationManager authenticationManager(BaseLdapPathContextSource contextSource) {
			LdapPasswordComparisonAuthenticationManagerFactory factory = new LdapPasswordComparisonAuthenticationManagerFactory(
					contextSource, NoOpPasswordEncoder.getInstance());
			factory.setPasswordAttribute("uid");
			factory.setUserDnPatterns("uid={0},ou=people");
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
