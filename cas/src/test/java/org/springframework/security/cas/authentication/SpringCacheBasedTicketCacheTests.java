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

package org.springframework.security.cas.authentication;

import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.cache.CacheManager;
import org.springframework.cache.concurrent.ConcurrentMapCacheManager;

import static org.assertj.core.api.Assertions.*;

/**
 * Tests
 * {@link org.springframework.security.cas.authentication.SpringCacheBasedTicketCache}.
 *
 * @author Marten Deinum
 * @since 3.2
 */
public class SpringCacheBasedTicketCacheTests extends AbstractStatelessTicketCacheTests {

	private static CacheManager cacheManager;

	// ~ Methods
	// ========================================================================================================

	@BeforeClass
	public static void initCacheManaer() {
		cacheManager = new ConcurrentMapCacheManager();
		cacheManager.getCache("castickets");
	}

	@Test
	public void testCacheOperation() throws Exception {
		SpringCacheBasedTicketCache cache = new SpringCacheBasedTicketCache(cacheManager.getCache("castickets"));

		final CasAuthenticationToken token = getToken();

		// Check it gets stored in the cache
		cache.putTicketInCache(token);
		assertThat(cache.getByTicketId("ST-0-ER94xMJmn6pha35CQRoZ")).isEqualTo(token);

		// Check it gets removed from the cache
		cache.removeTicketFromCache(getToken());
		assertThat(cache.getByTicketId("ST-0-ER94xMJmn6pha35CQRoZ")).isNull();

		// Check it doesn't return values for null or unknown service tickets
		assertThat(cache.getByTicketId(null)).isNull();
		assertThat(cache.getByTicketId("UNKNOWN_SERVICE_TICKET")).isNull();
	}

	@Test(expected = IllegalArgumentException.class)
	public void testStartupDetectsMissingCache() throws Exception {
		new SpringCacheBasedTicketCache(null);
	}

}
