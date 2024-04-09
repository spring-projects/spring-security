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

import java.util.List;

import org.springframework.util.Assert;

/**
 * A {@link UserDetailsService} that delegates to other {@link UserDetailsService}
 * instances.
 *
 * @author DingHao
 * @since 6.3
 */
public final class DelegatingUserDetailService implements UserDetailsService {

	private final List<UserDetailsService> delegates;

	private boolean continueOnError = false;

	public DelegatingUserDetailService(UserDetailsService... userDetailsServices) {
		this(List.of(userDetailsServices));
	}

	public DelegatingUserDetailService(List<UserDetailsService> userDetailsServices) {
		Assert.notEmpty(userDetailsServices, "userDetailsServices cannot be null");
		this.delegates = userDetailsServices;
	}

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		for (UserDetailsService userDetailsService : this.delegates) {
			try {
				UserDetails userDetails = userDetailsService.loadUserByUsername(username);
				if (userDetails != null) {
					return userDetails;
				}
			}
			catch (Exception ex) {
				if (this.continueOnError) {
					continue;
				}
				throw ex;
			}
		}
		throw new UsernameNotFoundException("User " + username + " not found");
	}

	/**
	 * Continue iterating when a delegate errors, defaults to {@code false}
	 * @param continueOnError whether to continue when a delegate errors
	 * @since 6.3
	 */
	public void setContinueOnError(boolean continueOnError) {
		this.continueOnError = continueOnError;
	}

}
