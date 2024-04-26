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

package org.springframework.security.provisioning;

import java.util.Collection;
import java.util.Properties;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.TestAuthentication;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.core.userdetails.PasswordEncodedUser;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * @author Rob Winch
 * @since 5.1
 */
public class InMemoryUserDetailsManagerTests {

	private final UserDetails user = PasswordEncodedUser.user();

	private InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager(this.user);

	@Test
	public void changePassword() {
		String newPassword = "newPassword";
		this.manager.updatePassword(this.user, newPassword);
		assertThat(this.manager.loadUserByUsername(this.user.getUsername()).getPassword()).isEqualTo(newPassword);
	}

	@Test
	public void changePasswordWhenUsernameIsNotInLowercase() {
		UserDetails userNotLowerCase = User.withUserDetails(PasswordEncodedUser.user()).username("User").build();
		String newPassword = "newPassword";
		this.manager.updatePassword(userNotLowerCase, newPassword);
		assertThat(this.manager.loadUserByUsername(userNotLowerCase.getUsername()).getPassword())
			.isEqualTo(newPassword);
	}

	@Test
	public void constructorWhenUserPropertiesThenCreate() {
		Properties properties = new Properties();
		properties.setProperty("joe", "{noop}joespassword,ROLE_A");
		properties.setProperty("bob", "{noop}bobspassword,ROLE_A,ROLE_B");
		InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager(properties);
		assertThat(manager.userExists("joe")).isTrue();
		assertThat(manager.userExists("bob")).isTrue();
	}

	@Test
	public void constructorWhenUserPropertiesWithEmptyValueThenException() {
		Properties properties = new Properties();
		properties.setProperty("joe", "");
		assertThatIllegalArgumentException().isThrownBy(() -> new InMemoryUserDetailsManager(properties))
			.withMessage("The entry with username 'joe' could not be converted to an UserDetails");
	}

	@Test
	public void constructorWhenUserPropertiesNoRolesThenException() {
		Properties properties = new Properties();
		properties.setProperty("joe", "{noop}joespassword");
		assertThatIllegalArgumentException().isThrownBy(() -> new InMemoryUserDetailsManager(properties))
			.withMessage("The entry with username 'joe' could not be converted to an UserDetails");
	}

	@Test
	public void changePasswordWhenCustomSecurityContextHolderStrategyThenUses() {
		Authentication authentication = TestAuthentication.authenticatedUser();
		InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager((User) authentication.getPrincipal());
		SecurityContextHolderStrategy strategy = mock(SecurityContextHolderStrategy.class);
		given(strategy.getContext()).willReturn(new SecurityContextImpl(authentication));
		manager.setSecurityContextHolderStrategy(strategy);
		manager.changePassword("password", "newpassword");
		verify(strategy).getContext();
	}

	@Test
	public void createUserWhenUserAlreadyExistsThenException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.manager.createUser(this.user))
			.withMessage("user should not exist");
	}

	@Test
	public void createUserWhenInstanceOfMutableUserDetailsThenChangePasswordWorks() {
		InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
		CustomUser user = new CustomUser(User.withUserDetails(PasswordEncodedUser.user()).build());
		Authentication authentication = TestAuthentication.authenticated(user);
		SecurityContextHolderStrategy strategy = mock(SecurityContextHolderStrategy.class);
		given(strategy.getContext()).willReturn(new SecurityContextImpl(authentication));
		manager.setSecurityContextHolderStrategy(strategy);
		manager.createUser(user);
		String newPassword = "newPassword";
		manager.changePassword(user.getPassword(), newPassword);
		assertThat(manager.loadUserByUsername(user.getUsername()).getPassword()).isEqualTo(newPassword);
	}

	@Test
	public void updateUserWhenUserDoesNotExistThenException() {
		InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
		assertThatIllegalArgumentException().isThrownBy(() -> manager.updateUser(this.user))
			.withMessage("user should exist");
	}

	@Test
	public void loadUserByUsernameWhenUserNullThenException() {
		InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
		assertThatExceptionOfType(UsernameNotFoundException.class)
			.isThrownBy(() -> manager.loadUserByUsername(this.user.getUsername()));
	}

	@Test
	public void loadUserByUsernameWhenNotInstanceOfCredentialsContainerThenReturnInstanceOfCredentialsContainer() {
		MutableUser user = new MutableUser(User.withUserDetails(PasswordEncodedUser.user()).build());
		InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager(user);
		assertThat(user).isNotInstanceOf(CredentialsContainer.class);
		assertThat(manager.loadUserByUsername(user.getUsername())).isInstanceOf(CredentialsContainer.class);
	}

	@Test
	public void loadUserByUsernameWhenInstanceOfCredentialsContainerThenReturnInstance() {
		CustomUser user = new CustomUser(User.withUserDetails(PasswordEncodedUser.user()).build());
		InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager(user);
		assertThat(manager.loadUserByUsername(user.getUsername())).isSameAs(user);
	}

	@ParameterizedTest
	@MethodSource("authenticationErrorCases")
	void authenticateWhenInvalidMissingOrMalformedIdThenException(String username, String password,
			String expectedMessage) {
		UserDetails user = User.builder().username(username).password(password).roles("USER").build();
		InMemoryUserDetailsManager userManager = new InMemoryUserDetailsManager(user);

		DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
		authenticationProvider.setUserDetailsService(userManager);
		authenticationProvider.setPasswordEncoder(PasswordEncoderFactories.createDelegatingPasswordEncoder());

		AuthenticationManager authManager = new ProviderManager(authenticationProvider);

		assertThatIllegalArgumentException()
			.isThrownBy(() -> authManager.authenticate(new UsernamePasswordAuthenticationToken(username, "password")))
			.withMessage(expectedMessage);
	}

	private static Stream<Arguments> authenticationErrorCases() {
		return Stream.of(Arguments
			.of("user", "password", "Given that there is no default password encoder configured, each "
					+ "password must have a password encoding prefix. Please either prefix this password with '{noop}' or set a default password encoder in `DelegatingPasswordEncoder`."),
				Arguments.of("user", "bycrpt}password",
						"The name of the password encoder is improperly formatted or incomplete. The format should be '{ENCODER}password'."),
				Arguments.of("user", "{bycrptpassword",
						"The name of the password encoder is improperly formatted or incomplete. The format should be '{ENCODER}password'."),
				Arguments.of("user", "{ren&stimpy}password",
						"There is no password encoder mapped for the id 'ren&stimpy'. Check your configuration to ensure it matches one of the registered encoders."));
	}

	static class CustomUser implements MutableUserDetails, CredentialsContainer {

		private final UserDetails delegate;

		private String password;

		CustomUser(UserDetails user) {
			this.delegate = user;
			this.password = user.getPassword();
		}

		@Override
		public Collection<? extends GrantedAuthority> getAuthorities() {
			return this.delegate.getAuthorities();
		}

		@Override
		public String getPassword() {
			return this.password;
		}

		@Override
		public void setPassword(final String password) {
			this.password = password;
		}

		@Override
		public String getUsername() {
			return this.delegate.getUsername();
		}

		@Override
		public void eraseCredentials() {
			this.password = null;
		}

	}

}
