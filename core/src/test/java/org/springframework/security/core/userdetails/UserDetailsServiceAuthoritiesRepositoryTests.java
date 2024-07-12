/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.core.userdetails;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * Tests for {@link UserDetailsServiceAuthoritiesRepository}
 *
 * @author Marcus da Coregio
 */
class UserDetailsServiceAuthoritiesRepositoryTests {

	UserDetailsService userDetailsService = new InMemoryUserDetailsManager(PasswordEncodedUser.user(),
			PasswordEncodedUser.admin());

	UserDetailsServiceAuthoritiesRepository userAuthoritiesRepository;

	@BeforeEach
	void setup() {
		this.userAuthoritiesRepository = new UserDetailsServiceAuthoritiesRepository(this.userDetailsService);
	}

	@Test
	void findUserAuthoritiesWhenUserExistsThenReturn() {
		UserAuthorities admin = this.userAuthoritiesRepository.findAuthoritiesByUsername("admin");
		assertThat(admin.getAuthorities()).extracting(GrantedAuthority::getAuthority)
			.containsExactly("ROLE_ADMIN", "ROLE_USER");
	}

	@Test
	void findUserAuthoritiesWhenUserDoesNotExistsThenUsernameNotFoundException() {
		assertThatExceptionOfType(UsernameNotFoundException.class)
			.isThrownBy(() -> this.userAuthoritiesRepository.findAuthoritiesByUsername("unknown"));
	}

}
