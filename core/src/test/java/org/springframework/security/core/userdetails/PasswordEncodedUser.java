/*
 * Copyright 2002-2017 the original author or authors.
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

import java.util.function.Function;

/**
 * @author Rob Winch
 * @since 5.0
 */
public class PasswordEncodedUser {

	private static final UserDetails USER = withUsername("user").password("password").roles("USER").build();

	private static final UserDetails ADMIN = withUsername("admin").password("password").roles("USER", "ADMIN").build();

	public static UserDetails user() {
		return User.withUserDetails(USER).build();
	}

	public static UserDetails admin() {
		return User.withUserDetails(ADMIN).build();
	}

	public static User.UserBuilder builder() {
		return User.builder().passwordEncoder(passwordEncoder());
	}

	public static User.UserBuilder withUsername(String username) {
		return builder().username(username);
	}

	public static User.UserBuilder withUserDetails(UserDetails userDetails) {
		return User.withUserDetails(userDetails).passwordEncoder(passwordEncoder());
	}

	private static Function<String, String> passwordEncoder() {
		return (rawPassword) -> "{noop}" + rawPassword;
	}

	protected PasswordEncodedUser() {
	}

}
