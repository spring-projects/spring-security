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
package org.springframework.security.samples.openid;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.openid.OpenIDAttribute;
import org.springframework.security.openid.OpenIDAuthenticationToken;

/**
 * Custom UserDetailsService which accepts any OpenID user, "registering" new users in a
 * map so they can be welcomed back to the site on subsequent logins.
 *
 * @deprecated The OpenID 1.0 and 2.0 protocols have been deprecated and users are
 *  <a href="https://openid.net/specs/openid-connect-migration-1_0.html">encouraged to migrate</a>
 *  to <a href="https://openid.net/connect/">OpenID Connect</a>, which is supported by <code>spring-security-oauth2</code>.
 * @author Luke Taylor
 * @since 3.1
 */
public class CustomUserDetailsService implements UserDetailsService,
		AuthenticationUserDetailsService<OpenIDAuthenticationToken> {

	private final Map<String, CustomUserDetails> registeredUsers = new HashMap<>();

	private static final List<GrantedAuthority> DEFAULT_AUTHORITIES = AuthorityUtils
			.createAuthorityList("ROLE_USER");

	/**
	 * Implementation of {@code UserDetailsService}. We only need this to satisfy the
	 * {@code RememberMeServices} requirements.
	 */
	public UserDetails loadUserByUsername(String id) throws UsernameNotFoundException {
		UserDetails user = registeredUsers.get(id);

		if (user == null) {
			throw new UsernameNotFoundException(id);
		}

		return user;
	}

	/**
	 * Implementation of {@code AuthenticationUserDetailsService} which allows full access
	 * to the submitted {@code Authentication} object. Used by the
	 * OpenIDAuthenticationProvider.
	 */
	public UserDetails loadUserDetails(OpenIDAuthenticationToken token) {
		String id = token.getIdentityUrl();

		CustomUserDetails user = registeredUsers.get(id);

		if (user != null) {
			return user;
		}

		String email = null;
		String firstName = null;
		String lastName = null;
		String fullName = null;

		List<OpenIDAttribute> attributes = token.getAttributes();

		for (OpenIDAttribute attribute : attributes) {
			if (attribute.getName().equals("email")) {
				email = attribute.getValues().get(0);
			}

			if (attribute.getName().equals("firstname")) {
				firstName = attribute.getValues().get(0);
			}

			if (attribute.getName().equals("lastname")) {
				lastName = attribute.getValues().get(0);
			}

			if (attribute.getName().equals("fullname")) {
				fullName = attribute.getValues().get(0);
			}
		}

		if (fullName == null) {
			StringBuilder fullNameBldr = new StringBuilder();

			if (firstName != null) {
				fullNameBldr.append(firstName);
			}

			if (lastName != null) {
				fullNameBldr.append(" ").append(lastName);
			}
			fullName = fullNameBldr.toString();
		}

		user = new CustomUserDetails(id, DEFAULT_AUTHORITIES);
		user.setEmail(email);
		user.setName(fullName);

		registeredUsers.put(id, user);

		user = new CustomUserDetails(id, DEFAULT_AUTHORITIES);
		user.setEmail(email);
		user.setName(fullName);
		user.setNewUser(true);

		return user;
	}
}
