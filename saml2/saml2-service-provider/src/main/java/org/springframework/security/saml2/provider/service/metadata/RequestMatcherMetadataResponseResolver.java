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

package org.springframework.security.saml2.provider.service.metadata;

import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * An implementation of {@link Saml2MetadataResponseResolver} that identifies which
 * {@link RelyingPartyRegistration}s to use with a {@link RequestMatcher}
 *
 * @author Josh Cummings
 * @since 6.1
 * @deprecated Please use
 * {@link org.springframework.security.saml2.provider.service.web.metadata.RequestMatcherMetadataResponseResolver}
 */
@Deprecated
public final class RequestMatcherMetadataResponseResolver extends
		org.springframework.security.saml2.provider.service.web.metadata.RequestMatcherMetadataResponseResolver {

	/**
	 * Construct a
	 * {@link org.springframework.security.saml2.provider.service.web.metadata.RequestMatcherMetadataResponseResolver}
	 * @param registrations the source for relying party metadata
	 * @param metadata the strategy for converting {@link RelyingPartyRegistration}s into
	 * metadata
	 */
	public RequestMatcherMetadataResponseResolver(RelyingPartyRegistrationRepository registrations,
			Saml2MetadataResolver metadata) {
		super(registrations, metadata);
	}

}
