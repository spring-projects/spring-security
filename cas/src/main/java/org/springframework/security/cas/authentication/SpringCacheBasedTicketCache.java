/*
 * Copyright 2002-2013 the original author or authors.
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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.cache.Cache;
import org.springframework.util.Assert;

/**
 * Caches tickets using a Spring IoC defined {@link Cache}.
 *
 * @author Marten Deinum
 * @since 3.2
 *
 */
public class SpringCacheBasedTicketCache implements StatelessTicketCache {
	// ~ Static fields/initializers
	// =====================================================================================

	private static final Log logger = LogFactory
			.getLog(SpringCacheBasedTicketCache.class);

	// ~ Instance fields
	// ================================================================================================

	private final Cache cache;

	// ~ Constructors
	// ===================================================================================================

	public SpringCacheBasedTicketCache(Cache cache) throws Exception {
		Assert.notNull(cache, "cache mandatory");
		this.cache = cache;
	}

	// ~ Methods
	// ========================================================================================================

	public CasAuthenticationToken getByTicketId(final String serviceTicket) {
		final Cache.ValueWrapper element = serviceTicket != null ? cache
				.get(serviceTicket) : null;

		if (logger.isDebugEnabled()) {
			logger.debug("Cache hit: " + (element != null) + "; service ticket: "
					+ serviceTicket);
		}

		return element == null ? null : (CasAuthenticationToken) element.get();
	}

	public void putTicketInCache(final CasAuthenticationToken token) {
		String key = token.getCredentials().toString();

		if (logger.isDebugEnabled()) {
			logger.debug("Cache put: " + key);
		}

		cache.put(key, token);
	}

	public void removeTicketFromCache(final CasAuthenticationToken token) {
		if (logger.isDebugEnabled()) {
			logger.debug("Cache remove: " + token.getCredentials().toString());
		}

		this.removeTicketFromCache(token.getCredentials().toString());
	}

	public void removeTicketFromCache(final String serviceTicket) {
		cache.evict(serviceTicket);
	}
}
