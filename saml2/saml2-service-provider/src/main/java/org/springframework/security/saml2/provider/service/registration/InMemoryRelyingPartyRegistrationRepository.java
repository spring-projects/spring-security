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

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.util.Assert;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

/**
 * An in-memory implementation of {@link RelyingPartyRegistrationRepository}. Also
 * implements {@link Iterable} to simplify the default login page.
 *
 * @author Filip Hanik
 * @author Josh Cummings
 * @since 5.2
 */
public class InMemoryRelyingPartyRegistrationRepository implements IterableRelyingPartyRegistrationRepository {

	private final Map<String, RelyingPartyRegistration> byRegistrationId;

	private final Map<String, List<RelyingPartyRegistration>> byAssertingPartyEntityId;

	public InMemoryRelyingPartyRegistrationRepository(RelyingPartyRegistration... registrations) {
		this(Arrays.asList(registrations));
	}

	public InMemoryRelyingPartyRegistrationRepository(Collection<RelyingPartyRegistration> registrations) {
		Assert.notEmpty(registrations, "registrations cannot be empty");
		this.byRegistrationId = createMappingToIdentityProvider(registrations);
		this.byAssertingPartyEntityId = createMappingByAssertingPartyEntityId(registrations);
	}

	private static Map<String, RelyingPartyRegistration> createMappingToIdentityProvider(
			Collection<RelyingPartyRegistration> rps) {
		LinkedHashMap<String, RelyingPartyRegistration> result = new LinkedHashMap<>();
		for (RelyingPartyRegistration rp : rps) {
			Assert.notNull(rp, "relying party collection cannot contain null values");
			String key = rp.getRegistrationId();
			Assert.notNull(key, "relying party identifier cannot be null");
			Assert.isNull(result.get(key), () -> "relying party duplicate identifier '" + key + "' detected.");
			result.put(key, rp);
		}
		return Collections.unmodifiableMap(result);
	}

	private static Map<String, List<RelyingPartyRegistration>> createMappingByAssertingPartyEntityId(
			Collection<RelyingPartyRegistration> rps) {
		MultiValueMap<String, RelyingPartyRegistration> result = new LinkedMultiValueMap<>();
		for (RelyingPartyRegistration rp : rps) {
			result.add(rp.getAssertingPartyMetadata().getEntityId(), rp);
		}
		return Collections.unmodifiableMap(result);
	}

	@Override
	public RelyingPartyRegistration findByRegistrationId(String id) {
		return this.byRegistrationId.get(id);
	}

	@Override
	public RelyingPartyRegistration findUniqueByAssertingPartyEntityId(String entityId) {
		Collection<RelyingPartyRegistration> registrations = this.byAssertingPartyEntityId.get(entityId);
		if (registrations == null) {
			return null;
		}
		if (registrations.size() > 1) {
			return null;
		}
		return registrations.iterator().next();
	}

	@Override
	public Iterator<RelyingPartyRegistration> iterator() {
		return this.byRegistrationId.values().iterator();
	}

}
