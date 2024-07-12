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

import org.springframework.util.Assert;

/**
 * An implementation of {@link UserAuthoritiesRepository} that uses a
 * {@link UserDetailsService} to load the user authorities.
 *
 * @author Marcus da Coregio
 * @since 6.4
 */
public class UserDetailsServiceAuthoritiesRepository implements UserAuthoritiesRepository {

	private final UserDetailsService userDetailsService;

	public UserDetailsServiceAuthoritiesRepository(UserDetailsService userDetailsService) {
		Assert.notNull(userDetailsService, "userDetailsService cannot be null");
		this.userDetailsService = userDetailsService;
	}

	@Override
	public UserAuthorities findAuthoritiesByUsername(String username) {
		return this.userDetailsService.loadUserByUsername(username);
	}

}
