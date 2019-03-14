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
package org.springframework.security.core.userdetails.cache;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.cache.Cache;
import org.springframework.security.core.userdetails.UserCache;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.Assert;

/**
 * Caches {@link UserDetails} instances in a Spring defined {@link Cache}.
 *
 * @author Marten Deinum
 * @since 3.2
 */
public class SpringCacheBasedUserCache implements UserCache {

	// ~ Static fields/initializers
	// =====================================================================================

	private static final Log logger = LogFactory.getLog(SpringCacheBasedUserCache.class);

	// ~ Instance fields
	// ================================================================================================

	private final Cache cache;

	// ~ Constructors
	// ===================================================================================================

	public SpringCacheBasedUserCache(Cache cache) throws Exception {
		Assert.notNull(cache, "cache mandatory");
		this.cache = cache;
	}

	// ~ Methods
	// ========================================================================================================

	public UserDetails getUserFromCache(String username) {
		Cache.ValueWrapper element = username != null ? cache.get(username) : null;

		if (logger.isDebugEnabled()) {
			logger.debug("Cache hit: " + (element != null) + "; username: " + username);
		}

		if (element == null) {
			return null;
		}
		else {
			return (UserDetails) element.get();
		}
	}

	public void putUserInCache(UserDetails user) {
		if (logger.isDebugEnabled()) {
			logger.debug("Cache put: " + user.getUsername());
		}
		cache.put(user.getUsername(), user);
	}

	public void removeUserFromCache(UserDetails user) {
		if (logger.isDebugEnabled()) {
			logger.debug("Cache remove: " + user.getUsername());
		}

		this.removeUserFromCache(user.getUsername());
	}

	public void removeUserFromCache(String username) {
		cache.evict(username);
	}
}
