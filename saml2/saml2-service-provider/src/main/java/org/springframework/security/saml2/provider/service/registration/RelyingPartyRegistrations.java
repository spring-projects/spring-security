/*
 * Copyright 2002-2020 the original author or authors.
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

import org.springframework.security.saml2.Saml2Exception;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

/**
 * A utility class for constructing instances of {@link RelyingPartyRegistration}
 *
 * @author Josh Cummings
 * @since 5.4
 */
public final class RelyingPartyRegistrations {

	private static final RestOperations rest = new RestTemplate(
			Arrays.asList(new OpenSamlRelyingPartyRegistrationBuilderHttpMessageConverter()));

	/**
	 * Return a {@link RelyingPartyRegistration.Builder} based off of the given SAML 2.0
	 * Asserting Party (IDP) metadata.
	 *
	 * Note that by default the registrationId is set to be the given metadata location,
	 * but this will most often not be sufficient. To complete the configuration, most
	 * applications will also need to provide a registrationId, like so:
	 *
	 * <pre>
	 *	RelyingPartyRegistration registration = RelyingPartyRegistrations
	 * 		.fromMetadataLocation(metadataLocation)
	 * 		.registrationId("registration-id")
	 * 		.build();
	 * </pre>
	 *
	 * Also note that an {@code IDPSSODescriptor} typically only contains information
	 * about the asserting party. Thus, you will need to remember to still populate
	 * anything about the relying party, like any private keys the relying party will use
	 * for signing AuthnRequests.
	 * @param metadataLocation
	 * @return the {@link RelyingPartyRegistration.Builder} for further configuration
	 */
	public static RelyingPartyRegistration.Builder fromMetadataLocation(String metadataLocation) {
		try {
			return rest.getForObject(metadataLocation, RelyingPartyRegistration.Builder.class);
		}
		catch (RestClientException e) {
			if (e.getCause() instanceof Saml2Exception) {
				throw (Saml2Exception) e.getCause();
			}
			throw new Saml2Exception(e);
		}
	}

}
