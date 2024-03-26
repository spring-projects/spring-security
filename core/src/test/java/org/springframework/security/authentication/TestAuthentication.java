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

package org.springframework.security.authentication;

import java.util.function.Consumer;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.PasswordEncodedUser;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * @author Rob Winch
 * @author Evgeniy Cheban
 * @since 5.0
 */
public class TestAuthentication extends PasswordEncodedUser {

	private static final Authentication ANONYMOUS = new AnonymousAuthenticationToken("key", "anonymous",
			AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));

	private static final RememberMeAuthenticationToken REMEMBER_ME = new RememberMeAuthenticationToken("key", "user",
			AuthorityUtils.createAuthorityList("ROLE_USER"));

	public static Authentication authenticatedAdmin() {
		return authenticated(admin());
	}

	public static Authentication authenticatedUser() {
		return authenticated(user());
	}

	public static Authentication authenticatedUser(Consumer<User.UserBuilder> consumer) {
		User.UserBuilder builder = withUsername("user");
		consumer.accept(builder);
		return authenticated(builder.build());
	}

	public static Authentication authenticated(UserDetails user) {
		return UsernamePasswordAuthenticationToken.authenticated(user, null, user.getAuthorities());
	}

	public static Authentication anonymousUser() {
		return ANONYMOUS;
	}

	public static Authentication rememberMeUser() {
		return REMEMBER_ME;
	}

}
