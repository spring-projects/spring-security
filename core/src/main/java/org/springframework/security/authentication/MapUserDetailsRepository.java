/*
 *
 *  * Copyright 2002-2017 the original author or authors.
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *      http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package org.springframework.security.authentication;

import java.util.Arrays;
import java.util.Collection;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import org.springframework.util.Assert;
import reactor.core.publisher.Mono;

/**
 *
 * @author Rob Winch
 * @since 5.0
 */
public class MapUserDetailsRepository implements UserDetailsRepository {
	private final Map<String,UserDetails> users;

	public MapUserDetailsRepository(Map<String,UserDetails> users) {
		this.users = users;
	}

	public MapUserDetailsRepository(UserDetails... users) {
		this(Arrays.asList(users));
	}

	public MapUserDetailsRepository(Collection<UserDetails> users) {
		Assert.notEmpty(users, "users cannot be null or empty");
		this.users = users.stream().collect(Collectors.toMap( u -> getKey(u.getName()), Function.identity()));
	}

	@Override
	public Mono<UserDetails> findByUsername(String username) {
		String key = getKey(username);
		UserDetails result = users.get(key);
		return result == null ? Mono.empty() : Mono.just(User.withUserDetails(result).build());
	}

	private String getKey(String username) {
		return username.toLowerCase();
	}
}
