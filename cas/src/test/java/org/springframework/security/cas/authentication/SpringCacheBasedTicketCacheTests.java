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

package org.springframework.security.cas.authentication;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.cache.concurrent.ConcurrentMapCacheManager;

import static org.junit.Assert.*;


/**
 * Tests {@link org.springframework.security.cas.authentication.SpringCacheBasedTicketCache}.
 *
 * @author Marten Deinum
 * @since 3.2
 */
public class SpringCacheBasedTicketCacheTests extends AbstractStatelessTicketCacheTests {
    private static CacheManager cacheManager;

    //~ Methods ========================================================================================================
    @BeforeClass
    public static void initCacheManaer() {
        cacheManager = new ConcurrentMapCacheManager();
        cacheManager.getCache("castickets");
    }

    @Test
    public void testCacheOperation() throws Exception {
        SpringCacheBasedTicketCache cache = new SpringCacheBasedTicketCache();
        cache.setCache(cacheManager.getCache("castickets"));
        cache.afterPropertiesSet();

        final CasAuthenticationToken token = getToken();

        // Check it gets stored in the cache
        cache.putTicketInCache(token);
        assertEquals(token, cache.getByTicketId("ST-0-ER94xMJmn6pha35CQRoZ"));

        // Check it gets removed from the cache
        cache.removeTicketFromCache(getToken());
        assertNull(cache.getByTicketId("ST-0-ER94xMJmn6pha35CQRoZ"));

        // Check it doesn't return values for null or unknown service tickets
        assertNull(cache.getByTicketId(null));
        assertNull(cache.getByTicketId("UNKNOWN_SERVICE_TICKET"));
    }

    @Test
    public void testStartupDetectsMissingCache() throws Exception {
        SpringCacheBasedTicketCache cache = new SpringCacheBasedTicketCache();

        try {
            cache.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }

        Cache myCache = cacheManager.getCache("castickets");
        cache.setCache(myCache);
        assertEquals(myCache, cache.getCache());
    }
}
