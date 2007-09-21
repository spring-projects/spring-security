/*
 * Copyright 2005-2007 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.providers.portlet.cache;

import net.sf.ehcache.Cache;
import net.sf.ehcache.CacheException;
import net.sf.ehcache.Element;

import org.springframework.security.providers.portlet.UserCache;
import org.springframework.security.userdetails.UserDetails;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.util.Assert;

/**
 * <code>UserCache</code> implementation for portlets that uses an injected
 * <a href="http://ehcache.sourceforge.net">ehcache</a>.
 *
 * @author John A. Lewis
 * @since 2.0
 * @version $Id$
 */
public class EhCacheBasedUserCache
		implements UserCache, InitializingBean {

	//~ Static fields/initializers =====================================================================================

	private static final Log logger = LogFactory.getLog(EhCacheBasedUserCache.class);

	//~ Instance fields ================================================================================================

	private Cache cache;

	//~ Methods ========================================================================================================

	public void afterPropertiesSet() throws Exception {
		Assert.notNull(cache, "cache mandatory");
	}

	public UserDetails getUserFromCache(String username) {

		Element element = null;

		try {
			element = cache.get(username);
		} catch (CacheException cacheException) {
			throw new DataRetrievalFailureException("Cache failure: "
					+ cacheException.getMessage());
		}

		if (logger.isDebugEnabled())
			logger.debug("Cache hit: " + (element != null) + "; username: " + username);

		return (element != null ? (UserDetails) element.getValue() : null);
	}

	public void putUserInCache(UserDetails user) {

		Element element = new Element(user.getUsername(), user);

		if (logger.isDebugEnabled())
			logger.debug("Cache put: " + element.getKey());

		cache.put(element);
	}

	public void removeUserFromCache(UserDetails user) {
		this.removeUserFromCache(user.getUsername());
	}

	public void removeUserFromCache(String username) {
		if (logger.isDebugEnabled())
			logger.debug("Cache remove: " + username);
		cache.remove(username);
	}


	public Cache getCache() {
		return cache;
	}

	public void setCache(Cache cache) {
		this.cache = cache;
	}

}
