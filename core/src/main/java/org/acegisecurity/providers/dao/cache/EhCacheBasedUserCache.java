/* Copyright 2004 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.sf.acegisecurity.providers.dao.cache;

import net.sf.acegisecurity.UserDetails;
import net.sf.acegisecurity.providers.dao.UserCache;

import net.sf.ehcache.Cache;
import net.sf.ehcache.CacheException;
import net.sf.ehcache.Element;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.factory.InitializingBean;

import org.springframework.dao.DataRetrievalFailureException;


/**
 * Caches <code>User</code> objects using a Spring IoC defined <A
 * HREF="http://ehcache.sourceforge.net">EHCACHE</a>.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class EhCacheBasedUserCache implements UserCache, InitializingBean {
    //~ Static fields/initializers =============================================

    private static final Log logger = LogFactory.getLog(EhCacheBasedUserCache.class);

    //~ Instance fields ========================================================

    private Cache cache;

    //~ Methods ================================================================

    public void setCache(Cache cache) {
        this.cache = cache;
    }

    public Cache getCache() {
        return cache;
    }

    public UserDetails getUserFromCache(String username) {
        Element element = null;

        try {
            element = cache.get(username);
        } catch (CacheException cacheException) {
            throw new DataRetrievalFailureException("Cache failure: "
                + cacheException.getMessage());
        }

        if (logger.isDebugEnabled()) {
            logger.debug("Cache hit: " + (element != null) + "; username: "
                + username);
        }

        if (element == null) {
            return null;
        } else {
            return (UserDetails) element.getValue();
        }
    }

    public void afterPropertiesSet() throws Exception {
        if (cache == null) {
            throw new IllegalArgumentException("cache mandatory");
        }
    }

    public void putUserInCache(UserDetails user) {
        Element element = new Element(user.getUsername(), user);

        if (logger.isDebugEnabled()) {
            logger.debug("Cache put: " + element.getKey());
        }

        cache.put(element);
    }

    public void removeUserFromCache(UserDetails user) {
        if (logger.isDebugEnabled()) {
            logger.debug("Cache remove: " + user.getUsername());
        }

        this.removeUserFromCache(user.getUsername());
    }

    public void removeUserFromCache(String username) {
        cache.remove(username);
    }
}
