/*
 * Copyright 2002-2021 the original author or authors.
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

import java.util.Properties;

import org.junit.Test;

import org.springframework.security.core.userdetails.PasswordEncodedUser;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

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

}
