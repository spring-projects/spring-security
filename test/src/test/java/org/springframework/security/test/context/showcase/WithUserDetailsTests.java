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

package org.springframework.security.test.context.showcase;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.test.context.showcase.service.HelloMessageService;
import org.springframework.security.test.context.showcase.service.MessageService;
import org.springframework.security.test.context.support.WithUserDetails;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * @author Rob Winch
 */
@ExtendWith(SpringExtension.class)
@ContextConfiguration(classes = WithUserDetailsTests.Config.class)
public class WithUserDetailsTests {

	@Autowired
	private MessageService messageService;

	@Test
	public void getMessageUnauthenticated() {
		assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> this.messageService.getMessage())
			.withRootCauseInstanceOf(AuthenticationCredentialsNotFoundException.class);
	}

	@Test
	@WithUserDetails
	public void getMessageWithUserDetails() {
		String message = this.messageService.getMessage();
		assertThat(message).contains("user");
		assertThat(getPrincipal()).isInstanceOf(CustomUserDetails.class);
	}

	@Test
	@WithUserDetails("customUsername")
	public void getMessageWithUserDetailsCustomUsername() {
		String message = this.messageService.getMessage();
		assertThat(message).contains("customUsername");
		assertThat(getPrincipal()).isInstanceOf(CustomUserDetails.class);
	}

	@Test
	@WithUserDetails(value = "customUsername", userDetailsServiceBeanName = "myUserDetailsService")
	public void getMessageWithUserDetailsServiceBeanName() {
		String message = this.messageService.getMessage();
		assertThat(message).contains("customUsername");
		assertThat(getPrincipal()).isInstanceOf(CustomUserDetails.class);
	}

	private Object getPrincipal() {
		return SecurityContextHolder.getContext().getAuthentication().getPrincipal();
	}

	@Configuration
	@EnableMethodSecurity
	@EnableWebSecurity
	@ComponentScan(basePackageClasses = HelloMessageService.class)
	static class Config {

		@Autowired
		void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
			auth.userDetailsService(myUserDetailsService());
		}

		@Bean
		UserDetailsService myUserDetailsService() {
			return new CustomUserDetailsService();
		}

	}

	static class CustomUserDetailsService implements UserDetailsService {

		@Override
		public UserDetails loadUserByUsername(final String username) throws UsernameNotFoundException {
			return new CustomUserDetails("name", username);
		}

	}

}
