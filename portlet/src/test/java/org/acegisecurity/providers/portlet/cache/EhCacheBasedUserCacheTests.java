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

package org.acegisecurity.providers.portlet.cache;

import java.io.IOException;

import junit.framework.TestCase;
import net.sf.ehcache.Cache;

import org.acegisecurity.providers.portlet.PortletTestUtils;
import org.springframework.cache.ehcache.EhCacheFactoryBean;

/**
 * Tests for {@link EhCacheBasedPortletUserCache}.
 *
 * @author John A. Lewis
 * @since 2.0
 * @version $Id$
 */
public class EhCacheBasedUserCacheTests extends TestCase {

	//~ Static fields/initializers =====================================================================================

	private static EhCacheFactoryBean cacheFactory;

	static {
		cacheFactory = new EhCacheFactoryBean();
		cacheFactory.setCacheName("portletUserCache");
		try {
			cacheFactory.afterPropertiesSet();
		} catch (IOException e) {
			throw new RuntimeException("unable to initialize cache factory", e);
		}
	}

	//~ Constructors ===================================================================================================

	public EhCacheBasedUserCacheTests() {
		super();
	}

	public EhCacheBasedUserCacheTests(String arg0) {
		super(arg0);
	}

	//~ Methods ========================================================================================================

	public final void setUp() throws Exception {
		super.setUp();
	}

	private Cache getCache() {
		return (Cache)cacheFactory.getObject();
	}

	public void testCacheOperation() throws Exception {

		// Create the cache
		EhCacheBasedUserCache cache = new EhCacheBasedUserCache();
		cache.setCache(getCache());
		cache.afterPropertiesSet();

		// Check it gets stored in the cache
		cache.putUserInCache(PortletTestUtils.createUser());
		assertEquals(PortletTestUtils.TESTCRED,
				cache.getUserFromCache(PortletTestUtils.TESTUSER).getPassword());

		// Check it gets removed from the cache
		cache.removeUserFromCache(PortletTestUtils.TESTUSER);
		assertNull(cache.getUserFromCache(PortletTestUtils.TESTUSER));

		// Check it doesn't return values for null user
		assertNull(cache.getUserFromCache(null));
	}

}
