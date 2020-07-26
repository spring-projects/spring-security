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
package org.springframework.security.provisioning;

import java.util.Collection;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsPasswordService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.core.userdetails.memory.UserAttribute;
import org.springframework.security.core.userdetails.memory.UserAttributeEditor;
import org.springframework.util.Assert;

/**
 * Non-persistent implementation of {@code UserDetailsManager} which is backed by an
 * in-memory map.
 * <p>
 * Mainly intended for testing and demonstration purposes, where a full blown persistent
 * system isn't required.
 *
 * @author Luke Taylor
 * @since 3.1
 */
public class InMemoryUserDetailsManager implements UserDetailsManager, UserDetailsPasswordService {

	protected final Log logger = LogFactory.getLog(getClass());

	private final Map<String, MutableUserDetails> users = new HashMap<>();

	private AuthenticationManager authenticationManager;

	public InMemoryUserDetailsManager() {
	}

	public InMemoryUserDetailsManager(Collection<UserDetails> users) {
		for (UserDetails user : users) {
			createUser(user);
		}
	}

	public InMemoryUserDetailsManager(UserDetails... users) {
		for (UserDetails user : users) {
			createUser(user);
		}
	}

	public InMemoryUserDetailsManager(Properties users) {
		Enumeration<?> names = users.propertyNames();
		UserAttributeEditor editor = new UserAttributeEditor();

		while (names.hasMoreElements()) {
			String name = (String) names.nextElement();
			editor.setAsText(users.getProperty(name));
			UserAttribute attr = (UserAttribute) editor.getValue();
			UserDetails user = new User(name, attr.getPassword(), attr.isEnabled(), true, true, true,
					attr.getAuthorities());
			createUser(user);
		}
	}

	public void createUser(UserDetails user) {
		Assert.isTrue(!userExists(user.getUsername()), "user should not exist");

		this.users.put(user.getUsername().toLowerCase(), new MutableUser(user));
	}

	public void deleteUser(String username) {
		this.users.remove(username.toLowerCase());
	}

	public void updateUser(UserDetails user) {
		Assert.isTrue(userExists(user.getUsername()), "user should exist");

		this.users.put(user.getUsername().toLowerCase(), new MutableUser(user));
	}

	public boolean userExists(String username) {
		return this.users.containsKey(username.toLowerCase());
	}

	public void changePassword(String oldPassword, String newPassword) {
		Authentication currentUser = SecurityContextHolder.getContext().getAuthentication();

		if (currentUser == null) {
			// This would indicate bad coding somewhere
			throw new AccessDeniedException(
					"Can't change password as no Authentication object found in context " + "for current user.");
		}

		String username = currentUser.getName();

		this.logger.debug("Changing password for user '" + username + "'");

		// If an authentication manager has been set, re-authenticate the user with the
		// supplied password.
		if (this.authenticationManager != null) {
			this.logger.debug("Reauthenticating user '" + username + "' for password change request.");

			this.authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, oldPassword));
		}
		else {
			this.logger.debug("No authentication manager set. Password won't be re-checked.");
		}

		MutableUserDetails user = this.users.get(username);

		if (user == null) {
			throw new IllegalStateException("Current user doesn't exist in database.");
		}

		user.setPassword(newPassword);
	}

	@Override
	public UserDetails updatePassword(UserDetails user, String newPassword) {
		String username = user.getUsername();
		MutableUserDetails mutableUser = this.users.get(username.toLowerCase());
		mutableUser.setPassword(newPassword);
		return mutableUser;
	}

	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		UserDetails user = this.users.get(username.toLowerCase());

		if (user == null) {
			throw new UsernameNotFoundException(username);
		}

		return new User(user.getUsername(), user.getPassword(), user.isEnabled(), user.isAccountNonExpired(),
				user.isCredentialsNonExpired(), user.isAccountNonLocked(), user.getAuthorities());
	}

	public void setAuthenticationManager(AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
	}

}
