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

package org.springframework.security.config.annotation.issue50;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.config.annotation.issue50.domain.User;
import org.springframework.security.config.annotation.issue50.repo.UserRepository;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.Assert;

/**
 * @author Rob Winch
 *
 */
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

	@Autowired
	private UserRepository myUserRepository;

	@Bean
	SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		// @formatter:off
		http
			.authorizeRequests()
				.requestMatchers(new AntPathRequestMatcher("/*")).permitAll()
				.and()
			.authenticationProvider(authenticationProvider());
		// @formatter:on
		return http.build();
	}

	@Bean
	AuthenticationManager authenticationManager() {
		return authenticationProvider()::authenticate;
	}

	@Bean
	public AuthenticationProvider authenticationProvider() {
		Assert.notNull(this.myUserRepository);
		return new AuthenticationProvider() {
			@Override
			public boolean supports(Class<?> authentication) {
				return true;
			}

			@Override
			public Authentication authenticate(Authentication authentication) throws AuthenticationException {
				Object principal = authentication.getPrincipal();
				String username = String.valueOf(principal);
				User user = SecurityConfig.this.myUserRepository.findByUsername(username);
				if (user == null) {
					throw new UsernameNotFoundException("No user for principal " + principal);
				}
				if (!authentication.getCredentials().equals(user.getPassword())) {
					throw new BadCredentialsException("Invalid password");
				}
				return new TestingAuthenticationToken(principal, null, "ROLE_USER");
			}
		};
	}

}
