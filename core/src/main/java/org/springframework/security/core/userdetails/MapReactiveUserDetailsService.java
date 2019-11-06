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

import java.util.Arrays;
import java.util.Collection;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.util.Assert;
import reactor.core.publisher.Mono;

/**
 * A {@link Map} based implementation of {@link ReactiveUserDetailsService}
 *
 * @author Rob Winch
 * @since 5.0
 */
public class MapReactiveUserDetailsService implements ReactiveUserDetailsService, ReactiveUserDetailsPasswordService {
	private final Map<String, UserDetails> users;

	/**
	 * Creates a new instance using a {@link Map} that must be non blocking.
	 * @param users a {@link Map} of users to use.
	 */
	public MapReactiveUserDetailsService(Map<String, UserDetails> users) {
		this.users = users;
	}

	/**
	 * Creates a new instance
	 * @param users the {@link UserDetails} to use
	 */
	public MapReactiveUserDetailsService(UserDetails... users) {
		this(Arrays.asList(users));
	}

	/**
	 * Creates a new instance
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
		UserDetails result = users.get(key);
		return result == null ? Mono.empty() : Mono.just(User.withUserDetails(result).build());
	}

	@Override
	public Mono<UserDetails> updatePassword(UserDetails user, String newPassword) {
		return Mono.just(user)
				.map(u ->
					User.withUserDetails(u)
						.password(newPassword)
						.build()
				)
				.doOnNext(u -> {
					String key = getKey(user.getUsername());
					this.users.put(key, u);
				});
	}

	private String getKey(String username) {
		return username.toLowerCase();
	}
}
