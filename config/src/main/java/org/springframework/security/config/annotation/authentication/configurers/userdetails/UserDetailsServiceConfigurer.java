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

package org.springframework.security.config.annotation.authentication.configurers.userdetails;

import org.springframework.security.config.annotation.authentication.ProviderManagerBuilder;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * Allows configuring a {@link UserDetailsService} within a
 * {@link AuthenticationManagerBuilder}.
 *
 * @param <B> the type of the {@link ProviderManagerBuilder}
 * @param <C> the {@link UserDetailsServiceConfigurer} (or this)
 * @param <U> the type of UserDetailsService being used to allow for returning the
 * concrete UserDetailsService.
 * @author Rob Winch
 * @since 3.2
 */
public class UserDetailsServiceConfigurer<B extends ProviderManagerBuilder<B>, C extends UserDetailsServiceConfigurer<B, C, U>, U extends UserDetailsService>
		extends AbstractDaoAuthenticationConfigurer<B, C, U> {

	/**
	 * Creates a new instance
	 * @param userDetailsService the {@link UserDetailsService} that should be used
	 */
	public UserDetailsServiceConfigurer(U userDetailsService) {
		super(userDetailsService);
	}

	@Override
	public void configure(B builder) {
		initUserDetailsService();
		super.configure(builder);
	}

	/**
	 * Allows subclasses to initialize the {@link UserDetailsService}. For example, it
	 * might add users, initialize schema, etc.
	 */
	protected void initUserDetailsService() {
	}

}
