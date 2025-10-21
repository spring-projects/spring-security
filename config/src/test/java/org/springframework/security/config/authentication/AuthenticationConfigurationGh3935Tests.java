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

package org.springframework.security.config.authentication;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.authentication.configuration.GlobalAuthenticationConfigurerAdapter;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.PasswordEncodedUser;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * @author Rob Winch
 */
@ExtendWith(SpringExtension.class)
@ContextConfiguration
public class AuthenticationConfigurationGh3935Tests {

	@Autowired
	FilterChainProxy springSecurityFilterChain;

	@Autowired
	UserDetailsService uds;

	@Autowired
	BootGlobalAuthenticationConfigurationAdapter adapter;

	// gh-3935
	@Test
	public void loads() {
		assertThat(this.springSecurityFilterChain).isNotNull();
	}

	@Test
	public void delegateUsesExisitingAuthentication() {
		String username = "user";
		String password = "password";
		given(this.uds.loadUserByUsername(username)).willReturn(PasswordEncodedUser.user());
		AuthenticationManager authenticationManager = this.adapter.authenticationManager;
		assertThat(authenticationManager).isNotNull();
		Authentication auth = authenticationManager
			.authenticate(UsernamePasswordAuthenticationToken.unauthenticated(username, password));
		verify(this.uds).loadUserByUsername(username);
		assertThat(auth.getPrincipal()).isEqualTo(PasswordEncodedUser.user());
	}

	@Configuration
	@EnableWebSecurity
	static class WebSecurity {

	}

	static class BootGlobalAuthenticationConfigurationAdapter extends GlobalAuthenticationConfigurerAdapter {

		private final ApplicationContext context;

		private AuthenticationManager authenticationManager;

		@Autowired
		BootGlobalAuthenticationConfigurationAdapter(ApplicationContext context) {
			this.context = context;
		}

		@Override
		public void init(AuthenticationManagerBuilder auth) {
			AuthenticationConfiguration configuration = this.context.getBean(AuthenticationConfiguration.class);
			this.authenticationManager = configuration.getAuthenticationManager();
		}

	}

	@Configuration
	static class AutoConfig {

		@Bean
		static BootGlobalAuthenticationConfigurationAdapter adapter(ApplicationContext context) {
			return new BootGlobalAuthenticationConfigurationAdapter(context);
		}

		@Bean
		UserDetailsService userDetailsService() {
			return mock(UserDetailsService.class);
		}

	}

}
