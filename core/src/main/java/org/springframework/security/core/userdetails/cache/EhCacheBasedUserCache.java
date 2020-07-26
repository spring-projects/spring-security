/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

import net.sf.ehcache.Ehcache;
import net.sf.ehcache.Element;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.core.userdetails.UserCache;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.Assert;

/**
 * Caches <code>User</code> objects using a Spring IoC defined
 * <A HREF="https://www.ehcache.org/">EHCACHE</a>.
 *
 * @author Ben Alex
 */
public class EhCacheBasedUserCache implements UserCache, InitializingBean {

	private static final Log logger = LogFactory.getLog(EhCacheBasedUserCache.class);

	private Ehcache cache;

	@Override
	public void afterPropertiesSet() {
		Assert.notNull(this.cache, "cache mandatory");
	}

	public Ehcache getCache() {
		return this.cache;
	}

	@Override
	public UserDetails getUserFromCache(String username) {
		Element element = this.cache.get(username);

		if (logger.isDebugEnabled()) {
			logger.debug("Cache hit: " + (element != null) + "; username: " + username);
		}

		if (element == null) {
			return null;
		}
		else {
			return (UserDetails) element.getValue();
		}
	}

	@Override
	public void putUserInCache(UserDetails user) {
		Element element = new Element(user.getUsername(), user);

		if (logger.isDebugEnabled()) {
			logger.debug("Cache put: " + element.getKey());
		}

		this.cache.put(element);
	}

	public void removeUserFromCache(UserDetails user) {
		if (logger.isDebugEnabled()) {
			logger.debug("Cache remove: " + user.getUsername());
		}

		this.removeUserFromCache(user.getUsername());
	}

	@Override
	public void removeUserFromCache(String username) {
		this.cache.remove(username);
	}

	public void setCache(Ehcache cache) {
		this.cache = cache;
	}

}
