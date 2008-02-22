/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.providers.dao.cache;


import net.sf.ehcache.Ehcache;
import net.sf.ehcache.CacheManager;
import net.sf.ehcache.Cache;

import org.springframework.security.GrantedAuthority;
import org.springframework.security.GrantedAuthorityImpl;

import org.springframework.security.userdetails.User;

import org.junit.BeforeClass;
import org.junit.AfterClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * Tests {@link EhCacheBasedUserCache}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class EhCacheBasedUserCacheTests {
    private static CacheManager cacheManager;

    //~ Methods ========================================================================================================
    @BeforeClass
    public static void initCacheManaer() {
        cacheManager = new CacheManager();
        cacheManager.addCache(new Cache("ehcacheusercachetests", 500, false, false, 30, 30));
    }

    @AfterClass
    public static void shutdownCacheManager() {
        cacheManager.removalAll();
        cacheManager.shutdown();
    }

    private Ehcache getCache() {
        Ehcache cache = cacheManager.getCache("ehcacheusercachetests");
        cache.removeAll();

        return cache;
    }

    private User getUser() {
        return new User("john", "password", true, true, true, true,
            new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl("ROLE_TWO")});
    }

    @Test
    public void cacheOperationsAreSuccessful() throws Exception {
        EhCacheBasedUserCache cache = new EhCacheBasedUserCache();
        cache.setCache(getCache());
        cache.afterPropertiesSet();

        // Check it gets stored in the cache
        cache.putUserInCache(getUser());
        assertEquals(getUser().getPassword(), cache.getUserFromCache(getUser().getUsername()).getPassword());

        // Check it gets removed from the cache
        cache.removeUserFromCache(getUser());
        assertNull(cache.getUserFromCache(getUser().getUsername()));

        // Check it doesn't return values for null or unknown users
        assertNull(cache.getUserFromCache(null));
        assertNull(cache.getUserFromCache("UNKNOWN_USER"));
    }

    @Test(expected = IllegalArgumentException.class)
    public void startupDetectsMissingCache() throws Exception {
        EhCacheBasedUserCache cache = new EhCacheBasedUserCache();

        cache.afterPropertiesSet();
        fail("Should have thrown IllegalArgumentException");

        Ehcache myCache = getCache();
        cache.setCache(myCache);
        assertEquals(myCache, cache.getCache());
    }
}
