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

package org.springframework.security.providers.x509.cache;

import net.sf.ehcache.Ehcache;
import net.sf.ehcache.CacheManager;
import net.sf.ehcache.Cache;

import org.springframework.security.GrantedAuthority;
import org.springframework.security.GrantedAuthorityImpl;

import org.springframework.security.providers.x509.X509TestUtils;

import org.springframework.security.userdetails.User;
import org.springframework.security.userdetails.UserDetails;


import org.junit.BeforeClass;
import org.junit.AfterClass;
import org.junit.Test;
import static org.junit.Assert.*;


/**
 * Tests for {@link EhCacheBasedX509UserCache}.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class EhCacheBasedX509UserCacheTests {
    private static CacheManager cacheManager;

    //~ Methods ========================================================================================================

    @BeforeClass
    public static void initCacheManaer() {
        cacheManager = new CacheManager();
        cacheManager.addCache(new Cache("x509cachetests", 500, false, false, 30, 30));
    }

    @AfterClass
    public static void shutdownCacheManager() {
        cacheManager.removalAll();
        cacheManager.shutdown();
    }

    private Ehcache getCache() {
        Ehcache cache = cacheManager.getCache("x509cachetests");
        cache.removeAll();

        return cache;
    }

    private UserDetails getUser() {
        return new User("rod", "password", true, true, true, true,
            new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl("ROLE_TWO")});
    }

    @Test
    public void cacheOperationsAreSucessful() throws Exception {
        EhCacheBasedX509UserCache cache = new EhCacheBasedX509UserCache();
        cache.setCache(getCache());
        cache.afterPropertiesSet();

        // Check it gets stored in the cache
        cache.putUserInCache(X509TestUtils.buildTestCertificate(), getUser());
        assertEquals(getUser().getPassword(), cache.getUserFromCache(X509TestUtils.buildTestCertificate()).getPassword());

        // Check it gets removed from the cache
        cache.removeUserFromCache(X509TestUtils.buildTestCertificate());
        assertNull(cache.getUserFromCache(X509TestUtils.buildTestCertificate()));

        // Check it doesn't return values for null user
        assertNull(cache.getUserFromCache(null));
    }
}
