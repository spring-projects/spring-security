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

import org.junit.jupiter.api.Test;

import org.springframework.security.core.authority.AuthorityUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * @author DingHao
 * @since 6.3
 */
public class DelegatingUserDetailServiceTests {

	DelegatingUserDetailService userDetailService = new DelegatingUserDetailService(new WebUserDetailsService(),
			new AppUserDetailsService());

	@Test
	public void applyWebUserDetailsService() {
		String username = "web";
		UserDetails userDetails = this.userDetailService.loadUserByUsername(username);
		assertThat(userDetails.getUsername()).isEqualTo(username);
	}

	@Test
	public void applyAppUserDetailsService() {
		this.userDetailService.setContinueOnError(true);
		String username = "app";
		UserDetails userDetails = this.userDetailService.loadUserByUsername(username);
		assertThat(userDetails.getUsername()).isEqualTo(username);
	}

	@Test
	public void applyUserDetailsServiceWithThrowException() {
		assertThatExceptionOfType(UsernameNotFoundException.class)
			.isThrownBy(() -> this.userDetailService.loadUserByUsername("admin"));
	}

	static class WebUserDetailsService implements UserDetailsService {

		@Override
		public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
			if ("web".equals(username)) {
				return new User(username, "pwd", AuthorityUtils.createAuthorityList("admin"));
			}
			if ("app".equals(username)) {
				throw new IllegalArgumentException(username + " login not allowed");
			}
			return null;
		}

	}

	static class AppUserDetailsService implements UserDetailsService {

		@Override
		public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
			if ("app".equals(username)) {
				return new User(username, "pwd", AuthorityUtils.createAuthorityList("user"));
			}
			return null;
		}

	}

}
