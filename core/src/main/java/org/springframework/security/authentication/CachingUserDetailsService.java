/*
 * Copyright 2002-2018 the original author or authors.
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
 * Implementation of {@link UserDetailsService} that utilizes caching through a {@link UserCache}.
 * <p>
 * If a null {@link UserDetails} instance is got from calling {@link UserCache#getUserFromCache(String)}
 * to the {@link UserCache} got from {@link #getUserCache()}, the user load is deferred to the {@link UserDetailsService}
 * provided during construction.
 * Otherwise, the instance got from cache is returned.
 * <p>
 * It is initialized with a {@link NullUserCache} by default, so it's strongly recommended setting your
 * own {@link UserCache} using {@link #setUserCache(UserCache)}, otherwise, the delegate will be called every time.
 * <p>
 * Utilize this class by defining {@link org.springframework.context.annotation.Bean}
 * that encapsulates an actual implementation of {@link UserDetailsService} and set an {@link UserCache}.
 * </p>
 * For example:
 * <pre>
 * {@code
 * @Bean
 * public CachingUserDetailsService cachingUserDetailsService(UserDetailsService delegate,
 *                                                            UserCache userCache) {
 *     CachingUserDetailsService service = new CachingUserDetailsService(delegate);
 *     service.setUserCache(userCache);
 *     return service;
 * }
 * }
 * </pre>
 * <p>
 * However, a preferable approach would be to use
 * {@link org.springframework.cache.annotation.Cacheable} in your {@link UserDetailsService#loadUserByUsername(String)}
 * implementation to cache {@link UserDetails} by <code>username</code>, reducing boilerplate and setup,
 * specially if you are already using cache in your application.
 * <br>
 * For example:
 * <pre>
 * {@code
 * @Service
 * public class MyCustomUserDetailsImplementation implements UserDetailsService {
 *
 *     @Override
 *     @Cacheable
 *     public UserDetails loadUserByUsername(String username) {
 *         //some code here to get the actual user details
 *         return userDetails;
 *     }
 * }
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
