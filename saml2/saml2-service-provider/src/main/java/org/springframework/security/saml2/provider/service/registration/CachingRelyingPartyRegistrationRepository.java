/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.saml2.provider.service.registration;

import java.util.Iterator;
import java.util.Spliterator;
import java.util.concurrent.Callable;
import java.util.function.Consumer;

import org.springframework.cache.Cache;
import org.springframework.cache.concurrent.ConcurrentMapCache;
import org.springframework.util.Assert;

/**
 * An {@link IterableRelyingPartyRegistrationRepository} that lazily queries and caches
 * metadata from a backing {@link IterableRelyingPartyRegistrationRepository}. Delegates
 * caching policies to Spring Cache.
 *
 * @author Josh Cummings
 * @since 6.4
 */
public final class CachingRelyingPartyRegistrationRepository implements IterableRelyingPartyRegistrationRepository {

	private final Callable<IterableRelyingPartyRegistrationRepository> registrationLoader;

	private Cache cache = new ConcurrentMapCache("registrations");

	public CachingRelyingPartyRegistrationRepository(Callable<IterableRelyingPartyRegistrationRepository> loader) {
		this.registrationLoader = loader;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Iterator<RelyingPartyRegistration> iterator() {
		return registrations().iterator();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public RelyingPartyRegistration findByRegistrationId(String registrationId) {
		return registrations().findByRegistrationId(registrationId);
	}

	@Override
	public RelyingPartyRegistration findUniqueByAssertingPartyEntityId(String entityId) {
		return registrations().findUniqueByAssertingPartyEntityId(entityId);
	}

	@Override
	public void forEach(Consumer<? super RelyingPartyRegistration> action) {
		registrations().forEach(action);
	}

	@Override
	public Spliterator<RelyingPartyRegistration> spliterator() {
		return registrations().spliterator();
	}

	private IterableRelyingPartyRegistrationRepository registrations() {
		return this.cache.get("registrations", this.registrationLoader);
	}

	/**
	 * Use this cache for the completed {@link RelyingPartyRegistration} instances.
	 *
	 * <p>
	 * Defaults to {@link ConcurrentMapCache}, meaning that the registrations are cached
	 * without expiry. To turn off the cache, use
	 * {@link org.springframework.cache.support.NoOpCache}.
	 * @param cache the {@link Cache} to use
	 */
	public void setCache(Cache cache) {
		Assert.notNull(cache, "cache cannot be null");
		this.cache = cache;
	}

}
