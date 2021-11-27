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

package org.springframework.security.core.userdetails;

import java.util.Arrays;
import java.util.Collection;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.util.Assert;
import reactor.core.publisher.Mono;

/**
 * A {@link Map} based implementation of {@link ReactiveUserDetailsService}
 *
 * @author Rob Winch
 * @since 5.0
 */
public class MapReactiveUserDetailsService implements ReactiveUserDetailsService, ReactiveUserDetailsPasswordService {
	private final Log logger = LogFactory.getLog(MapReactiveUserDetailsService.class);

	private final Map<String, UserDetails> users;
	private AuthenticationManager authenticationManager;

	/**
	 * Creates a new instance using a {@link Map}
	 * 
	 * @param users a {@link Map} of users to use.
	 */
	public MapReactiveUserDetailsService(Map<String, UserDetails> users) {
		this.users = new ConcurrentHashMap<>(users);
	}

	/**
	 * Creates a new instance
	 * 
	 * @param users the {@link UserDetails} to use
	 */
	public MapReactiveUserDetailsService(UserDetails... users) {
		this(Arrays.asList(users));
	}

	/**
	 * Creates a new instance
	 * 
	 * @param users the {@link UserDetails} to use
	 */
	public MapReactiveUserDetailsService(Collection<UserDetails> users) {
		Assert.notEmpty(users, "users cannot be null or empty");
		this.users = new ConcurrentHashMap<>();
		for (UserDetails user : users) {
			this.users.put(getKey(user.getUsername()), user);
		}
	}

	@Override
	public Mono<UserDetails> findByUsername(String username) {
		String key = getKey(username);
		UserDetails result = this.users.get(key);
		return (result != null) ? Mono.just(User.withUserDetails(result).build()) : Mono.empty();
	}

	@Override
	public Mono<UserDetails> updatePassword(UserDetails user, String newPassword) {
		// @formatter:off
		return Mono.just(user)
				.map((userDetails) -> withNewPassword(userDetails, newPassword))
				.doOnNext((userDetails) -> {
					String key = getKey(user.getUsername());
					this.users.put(key, userDetails);
				});
		// @formatter:on
	}

	private UserDetails withNewPassword(UserDetails userDetails, String newPassword) {
		// @formatter:off
		return User.withUserDetails(userDetails)
				.password(newPassword)
				.build();
		// @formatter:on
	}

	public Mono<Void> createUser(UserDetails user) {
		return userExists(user.getUsername()).doOnNext(exists -> Assert.isTrue(!exists, "user should not exist"))
				.thenReturn(getKey(user.getUsername())).doOnNext(key -> this.users.put(key, user)).then();
	}

	public Mono<Void> updateUser(UserDetails user) {
		return userExists(user.getUsername()).doOnNext(exists -> Assert.isTrue(exists, "user should exist"))
				.thenReturn(getKey(user.getUsername())).doOnNext(key -> this.users.put(key, user)).then();
	}

	public Mono<Void> deleteUser(String username) {
		return Mono.just(getKey(username)).doOnNext(this.users::remove).then();
	}

	public Mono<Boolean> userExists(String username) {
		return Mono.just(getKey(username)).map(this.users::containsKey);
	}

	public Mono<Void> changePassword(String oldPassword, String newPassword) {
		return Mono.from(ReactiveSecurityContextHolder.getContext()).map(securityContext -> {
			Authentication currentUser = securityContext.getAuthentication();
			if (currentUser == null) {
				throw new AccessDeniedException(
						"Can't change password as no Authentication object found in context for current user.");
			}
			return currentUser;
		}).map(Authentication::getName).doOnNext(username -> {
			if (authenticationManager != null) {
				logger.debug("Reauthenticating user '" + username + "' for password change request.");
				authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, oldPassword));
			} else {
				logger.debug("No authentication manager set. Password won't be re-checked.");
			}
		}).flatMap(this::findByUsername)
				.switchIfEmpty(Mono.error(new IllegalStateException("Current user doesn't exist in map.")))
				.flatMap(user -> updatePassword(user, newPassword)).then();
	}

	public void setAuthenticationManager(AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
	}

	private String getKey(String username) {
		return username.toLowerCase();
	}

}
