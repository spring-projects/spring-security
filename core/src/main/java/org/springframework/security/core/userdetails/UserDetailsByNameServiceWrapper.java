/*
 * Copyright 2002-2016 the original author or authors.
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

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

/**
 * This implementation for AuthenticationUserDetailsService wraps a regular Spring
 * Security UserDetailsService implementation, to retrieve a UserDetails object based on
 * the user name contained in an <tt>Authentication</tt> object.
 *
 * @author Ruud Senden
 * @author Scott Battaglia
 * @since 2.0
 */
public class UserDetailsByNameServiceWrapper<T extends Authentication> implements
		AuthenticationUserDetailsService<T>, InitializingBean {
	private UserDetailsService userDetailsService = null;

	/**
	 * Constructs an empty wrapper for compatibility with Spring Security 2.0.x's method
	 * of using a setter.
	 */
	public UserDetailsByNameServiceWrapper() {
		// constructor for backwards compatibility with 2.0
	}

	/**
	 * Constructs a new wrapper using the supplied
	 * {@link org.springframework.security.core.userdetails.UserDetailsService} as the
	 * service to delegate to.
	 *
	 * @param userDetailsService the UserDetailsService to delegate to.
	 */
	public UserDetailsByNameServiceWrapper(final UserDetailsService userDetailsService) {
		Assert.notNull(userDetailsService, "userDetailsService cannot be null.");
		this.userDetailsService = userDetailsService;
	}

	/**
	 * Check whether all required properties have been set.
	 *
	 * @see org.springframework.beans.factory.InitializingBean#afterPropertiesSet()
	 */
	public void afterPropertiesSet() throws Exception {
		Assert.notNull(this.userDetailsService, "UserDetailsService must be set");
	}

	/**
	 * Get the UserDetails object from the wrapped UserDetailsService implementation
	 */
	public UserDetails loadUserDetails(T authentication) throws UsernameNotFoundException {
		return this.userDetailsService.loadUserByUsername(authentication.getName());
	}

	/**
	 * Set the wrapped UserDetailsService implementation
	 *
	 * @param aUserDetailsService The wrapped UserDetailsService to set
	 */
	public void setUserDetailsService(UserDetailsService aUserDetailsService) {
		this.userDetailsService = aUserDetailsService;
	}
}
