/*
 * Copyright 2002-2013 the original author or authors.
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
package org.springframework.security.config.annotation.authentication.configurers.provisioning;

import java.util.ArrayList;
import java.util.List;

import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.config.annotation.authentication.ProviderManagerBuilder;
import org.springframework.security.config.annotation.authentication.configurers.userdetails.UserDetailsServiceConfigurer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.User.UserBuilder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.UserDetailsManager;

/**
 * Base class for populating an
 * {@link org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder}
 * with a {@link UserDetailsManager}.
 *
 * @param <B> the type of the {@link SecurityBuilder} that is being configured
 * @param <C> the type of {@link UserDetailsManagerConfigurer}
 *
 * @author Rob Winch
 * @since 3.2
 */
public class UserDetailsManagerConfigurer<B extends ProviderManagerBuilder<B>, C extends UserDetailsManagerConfigurer<B, C>>
		extends UserDetailsServiceConfigurer<B, C, UserDetailsManager> {

	private final List<UserDetailsBuilder> userBuilders = new ArrayList<UserDetailsBuilder>();

	protected UserDetailsManagerConfigurer(UserDetailsManager userDetailsManager) {
		super(userDetailsManager);
	}

	/**
	 * Populates the users that have been added.
	 *
	 * @throws Exception
	 */
	@Override
	protected void initUserDetailsService() throws Exception {
		for (UserDetailsBuilder userBuilder : userBuilders) {
			getUserDetailsService().createUser(userBuilder.build());
		}
	}

	/**
	 * Allows adding a user to the {@link UserDetailsManager} that is being created. This
	 * method can be invoked multiple times to add multiple users.
	 *
	 * @param username the username for the user being added. Cannot be null.
	 * @return
	 */
	@SuppressWarnings("unchecked")
	public final UserDetailsBuilder withUser(String username) {
		UserDetailsBuilder userBuilder = new UserDetailsBuilder((C) this);
		userBuilder.username(username);
		this.userBuilders.add(userBuilder);
		return userBuilder;
	}

	/**
	 * Builds the user to be added. At minimum the username, password, and authorities
	 * should provided. The remaining attributes have reasonable defaults.
	 */
	public class UserDetailsBuilder {
		private UserBuilder user;
		private final C builder;

		/**
		 * Creates a new instance
		 * @param builder the builder to return
		 */
		private UserDetailsBuilder(C builder) {
			this.builder = builder;
		}

		/**
		 * Returns the {@link UserDetailsManagerConfigurer} for method chaining (i.e. to add
		 * another user)
		 *
		 * @return the {@link UserDetailsManagerConfigurer} for method chaining
		 */
		public C and() {
			return builder;
		}

		/**
		 * Populates the username. This attribute is required.
		 *
		 * @param username the username. Cannot be null.
		 * @return the {@link UserDetailsBuilder} for method chaining (i.e. to populate
		 * additional attributes for this user)
		 */
		private UserDetailsBuilder username(String username) {
			this.user = User.withUsername(username);
			return this;
		}

		/**
		 * Populates the password. This attribute is required.
		 *
		 * @param password the password. Cannot be null.
		 * @return the {@link UserDetailsBuilder} for method chaining (i.e. to populate
		 * additional attributes for this user)
		 */
		public UserDetailsBuilder password(String password) {
			this.user.password(password);
			return this;
		}

		/**
		 * Populates the roles. This method is a shortcut for calling
		 * {@link #authorities(String...)}, but automatically prefixes each entry with
		 * "ROLE_". This means the following:
		 *
		 * <code>
		 *     builder.roles("USER","ADMIN");
		 * </code>
		 *
		 * is equivalent to
		 *
		 * <code>
		 *     builder.authorities("ROLE_USER","ROLE_ADMIN");
		 * </code>
		 *
		 * <p>
		 * This attribute is required, but can also be populated with
		 * {@link #authorities(String...)}.
		 * </p>
		 *
		 * @param roles the roles for this user (i.e. USER, ADMIN, etc). Cannot be null,
		 * contain null values or start with "ROLE_"
		 * @return the {@link UserDetailsBuilder} for method chaining (i.e. to populate
		 * additional attributes for this user)
		 */
		public UserDetailsBuilder roles(String... roles) {
			this.user.roles(roles);
			return this;
		}

		/**
		 * Populates the authorities. This attribute is required.
		 *
		 * @param authorities the authorities for this user. Cannot be null, or contain
		 * null values
		 * @return the {@link UserDetailsBuilder} for method chaining (i.e. to populate
		 * additional attributes for this user)
		 * @see #roles(String...)
		 */
		public UserDetailsBuilder authorities(GrantedAuthority... authorities) {
			this.user.authorities(authorities);
			return this;
		}

		/**
		 * Populates the authorities. This attribute is required.
		 *
		 * @param authorities the authorities for this user. Cannot be null, or contain
		 * null values
		 * @return the {@link UserDetailsBuilder} for method chaining (i.e. to populate
		 * additional attributes for this user)
		 * @see #roles(String...)
		 */
		public UserDetailsBuilder authorities(List<? extends GrantedAuthority> authorities) {
			this.user.authorities(authorities);
			return this;
		}

		/**
		 * Populates the authorities. This attribute is required.
		 *
		 * @param authorities the authorities for this user (i.e. ROLE_USER, ROLE_ADMIN,
		 * etc). Cannot be null, or contain null values
		 * @return the {@link UserDetailsBuilder} for method chaining (i.e. to populate
		 * additional attributes for this user)
		 * @see #roles(String...)
		 */
		public UserDetailsBuilder authorities(String... authorities) {
			this.user.authorities(authorities);
			return this;
		}

		/**
		 * Defines if the account is expired or not. Default is false.
		 *
		 * @param accountExpired true if the account is expired, false otherwise
		 * @return the {@link UserDetailsBuilder} for method chaining (i.e. to populate
		 * additional attributes for this user)
		 */
		public UserDetailsBuilder accountExpired(boolean accountExpired) {
			this.user.accountExpired(accountExpired);
			return this;
		}

		/**
		 * Defines if the account is locked or not. Default is false.
		 *
		 * @param accountLocked true if the account is locked, false otherwise
		 * @return the {@link UserDetailsBuilder} for method chaining (i.e. to populate
		 * additional attributes for this user)
		 */
		public UserDetailsBuilder accountLocked(boolean accountLocked) {
			this.user.accountLocked(accountLocked);
			return this;
		}

		/**
		 * Defines if the credentials are expired or not. Default is false.
		 *
		 * @param credentialsExpired true if the credentials are expired, false otherwise
		 * @return the {@link UserDetailsBuilder} for method chaining (i.e. to populate
		 * additional attributes for this user)
		 */
		public UserDetailsBuilder credentialsExpired(boolean credentialsExpired) {
			this.user.credentialsExpired(credentialsExpired);
			return this;
		}

		/**
		 * Defines if the account is disabled or not. Default is false.
		 *
		 * @param disabled true if the account is disabled, false otherwise
		 * @return the {@link UserDetailsBuilder} for method chaining (i.e. to populate
		 * additional attributes for this user)
		 */
		public UserDetailsBuilder disabled(boolean disabled) {
			this.user.disabled(disabled);
			return this;
		}

		private UserDetails build() {
			return this.user.build();
		}
	}
}
