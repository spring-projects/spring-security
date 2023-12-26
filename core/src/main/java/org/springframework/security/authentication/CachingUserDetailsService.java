/*
 * Copyright 2002-2023 the original author or authors.
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

import org.springframework.security.core.userdetails.UserCache;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.cache.NullUserCache;
import org.springframework.util.Assert;

/**
 * Implementation of {@link UserDetailsService} that utilizes caching through a
 * {@link UserCache}
 * <p>
 * If a null {@link UserDetails} instance is returned from
 * {@link UserCache#getUserFromCache(String)} to the {@link UserCache} got from
 * {@link #getUserCache()}, the user load is deferred to the {@link UserDetailsService}
 * provided during construction. Otherwise, the instance retrieved from the cache is
 * returned.
 * <p>
 * It is initialized with a {@link NullUserCache} by default, so it's strongly recommended
 * setting your own {@link UserCache} using {@link #setUserCache(UserCache)}, otherwise,
 * the delegate will be called every time.
 * <p>
 * Utilize this class by defining a {@link org.springframework.context.annotation.Bean}
 * that encapsulates an actual implementation of {@link UserDetailsService} and providing
 * a {@link UserCache} implementation.
 * </p>
 * For example: <pre>
 * &#64;Bean
 * public CachingUserDetailsService cachingUserDetailsService(UserCache userCache) {
 *     UserDetailsService delegate = ...;
 *     CachingUserDetailsService service = new CachingUserDetailsService(delegate);
 *     service.setUserCache(userCache);
 *     return service;
 * }
 * </pre>
 *
 * @author Luke Taylor
 * @since 2.0
 */
public class CachingUserDetailsService implements UserDetailsService {

	private UserCache userCache = new NullUserCache();

	private final UserDetailsService delegate;

	public CachingUserDetailsService(UserDetailsService delegate) {
		this.delegate = delegate;
	}

	public UserCache getUserCache() {
		return this.userCache;
	}

	public void setUserCache(UserCache userCache) {
		this.userCache = userCache;
	}

	@Override
	public UserDetails loadUserByUsername(String username) {
		UserDetails user = this.userCache.getUserFromCache(username);
		if (user == null) {
			user = this.delegate.loadUserByUsername(username);
		}
		Assert.notNull(user, () -> "UserDetailsService " + this.delegate + " returned null for username " + username
				+ ". " + "This is an interface contract violation");
		this.userCache.putUserInCache(user);
		return user;
	}

}
