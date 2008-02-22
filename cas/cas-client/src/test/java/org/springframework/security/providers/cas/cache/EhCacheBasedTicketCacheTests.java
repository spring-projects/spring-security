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

package org.springframework.security.providers.cas.cache;

import net.sf.ehcache.Ehcache;
import net.sf.ehcache.CacheManager;
import net.sf.ehcache.Cache;

import org.springframework.security.GrantedAuthority;
import org.springframework.security.GrantedAuthorityImpl;

import org.springframework.security.providers.cas.CasAuthenticationToken;

import org.springframework.security.userdetails.User;
import java.util.List;
import java.util.Vector;

import org.junit.Test;
import org.junit.BeforeClass;
import org.junit.AfterClass;
import static org.junit.Assert.*;


/**
 * Tests {@link EhCacheBasedTicketCache}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class EhCacheBasedTicketCacheTests {
    private static CacheManager cacheManager;

    //~ Methods ========================================================================================================
    @BeforeClass
    public static void initCacheManaer() {
        cacheManager = new CacheManager();
        cacheManager.addCache(new Cache("castickets", 500, false, false, 30, 30));
    }

    @AfterClass
    public static void shutdownCacheManager() {
        cacheManager.removalAll();
        cacheManager.shutdown();
    }

    private CasAuthenticationToken getToken() {
        List proxyList = new Vector();
        proxyList.add("https://localhost/newPortal/j_spring_cas_security_check");

        User user = new User("rod", "password", true, true, true, true,
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl("ROLE_TWO")});

        return new CasAuthenticationToken("key", user, "ST-0-ER94xMJmn6pha35CQRoZ",
            new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl("ROLE_TWO")}, user,
            proxyList, "PGTIOU-0-R0zlgrl4pdAQwBvJWO3vnNpevwqStbSGcq3vKB2SqSFFRnjPHt");
    }

    @Test
    public void testCacheOperation() throws Exception {
        EhCacheBasedTicketCache cache = new EhCacheBasedTicketCache();
        cache.setCache(cacheManager.getCache("castickets"));
        cache.afterPropertiesSet();

        // Check it gets stored in the cache
        cache.putTicketInCache(getToken());
        assertEquals(getToken(), cache.getByTicketId("ST-0-ER94xMJmn6pha35CQRoZ"));

        // Check it gets removed from the cache
        cache.removeTicketFromCache(getToken());
        assertNull(cache.getByTicketId("ST-0-ER94xMJmn6pha35CQRoZ"));

        // Check it doesn't return values for null or unknown service tickets
        assertNull(cache.getByTicketId(null));
        assertNull(cache.getByTicketId("UNKNOWN_SERVICE_TICKET"));
    }

    @Test
    public void testStartupDetectsMissingCache() throws Exception {
        EhCacheBasedTicketCache cache = new EhCacheBasedTicketCache();

        try {
            cache.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }

        Ehcache myCache = cacheManager.getCache("castickets");
        cache.setCache(myCache);
        assertEquals(myCache, cache.getCache());
    }
}
