/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.saml2.provider.service.authentication;

import java.time.Instant;

import org.opensaml.storage.ReplayCache;

import org.springframework.cache.Cache;

/**
 * For internal use only.
 */
final class SpringCacheReplayCache implements ReplayCache {

	private final Cache cache;

	SpringCacheReplayCache(Cache cache) {
		this.cache = cache;
	}

	@Override
	public boolean check(String context, String key, Instant expires) {
		Cache.ValueWrapper existing = this.cache.get(context);
		if (existing != null) {
			Instant storedExpiry = (Instant) existing.get();
			if (storedExpiry != null && Instant.now().isBefore(storedExpiry)) {
				return false;
			}
		}
		this.cache.put(context, expires);
		return true;
	}

}
