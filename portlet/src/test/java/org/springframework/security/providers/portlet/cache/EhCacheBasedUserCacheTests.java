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
import net.sf.ehcache.CacheManager;

import org.springframework.security.providers.portlet.PortletTestUtils;

import org.junit.Test;
import org.junit.BeforeClass;
import org.junit.AfterClass;
import static org.junit.Assert.*;

/**
 * Tests for {@link EhCacheBasedUserCache}.
 *
 * @author John A. Lewis
 * @since 2.0
 * @version $Id$
 */
public class EhCacheBasedUserCacheTests {
    //~ Static fields/initializers =====================================================================================

    private static CacheManager cacheManager;

    @BeforeClass
    public static void initCacheManaer() {
        cacheManager = new CacheManager();
        cacheManager.addCache(new Cache("portletusercachetests", 500, false, false, 30, 30));
    }

    @AfterClass
    public static void shutdownCacheManager() {
        cacheManager.removalAll();
        cacheManager.shutdown();
    }

    private Cache getCache() {
        Cache cache = cacheManager.getCache("portletusercachetests");
        cache.removeAll();

        return cache;
    }

    @Test
    public void testCacheOperation() throws Exception {

		// Create the cache
		EhCacheBasedUserCache cache = new EhCacheBasedUserCache();
		cache.setCache(getCache());
		cache.afterPropertiesSet();

		// Check it gets stored in the cache
		cache.putUserInCache(PortletTestUtils.createUser());
		assertEquals(PortletTestUtils.TESTCRED, cache.getUserFromCache(PortletTestUtils.TESTUSER).getPassword());

		// Check it gets removed from the cache
		cache.removeUserFromCache(PortletTestUtils.TESTUSER);
		assertNull(cache.getUserFromCache(PortletTestUtils.TESTUSER));

		// Check it doesn't return values for null user
		assertNull(cache.getUserFromCache(null));
	}

}
