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

import org.springframework.lang.Nullable;

/**
 * A repository for retrieving SAML 2.0 Asserting Party Metadata
 *
 * @author Josh Cummings
 * @since 6.4
 * @see BaseOpenSamlAssertingPartyMetadataRepository
 * @see org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations
 */
public interface AssertingPartyMetadataRepository extends Iterable<AssertingPartyMetadata> {

	/**
	 * Retrieve an {@link AssertingPartyMetadata} by its <a href=
	 * "https://www.oasis-open.org/committees/download.php/51890/SAML%20MD%20simplified%20overview.pdf#2.9%20EntityDescriptor">EntityID</a>.
	 * @param entityId the EntityID to lookup
	 * @return the found {@link AssertingPartyMetadata}, or {@code null} otherwise
	 */
	@Nullable
	default AssertingPartyMetadata findByEntityId(String entityId) {
		for (AssertingPartyMetadata metadata : this) {
			if (metadata.getEntityId().equals(entityId)) {
				return metadata;
			}
		}
		return null;
	}

}
