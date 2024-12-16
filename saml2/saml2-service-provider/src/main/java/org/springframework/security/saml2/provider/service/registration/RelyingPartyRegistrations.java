/*
 * Copyright 2002-2023 the original author or authors.
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

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;

import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;

import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.ResourceLoader;
import org.springframework.security.saml2.Saml2Exception;

/**
 * A utility class for constructing instances of {@link RelyingPartyRegistration}
 *
 * @author Josh Cummings
 * @author Ryan Cassar
 * @author Marcus da Coregio
 * @since 5.4
 */
public final class RelyingPartyRegistrations {

	private static final ResourceLoader resourceLoader = new DefaultResourceLoader();

	private RelyingPartyRegistrations() {
	}

	/**
	 * Return a {@link RelyingPartyRegistration.Builder} based off of the given SAML 2.0
	 * Asserting Party (IDP) metadata location.
	 *
	 * Valid locations can be classpath- or file-based or they can be HTTPS endpoints.
	 * Some valid endpoints might include:
	 *
	 * <pre>
	 *   metadataLocation = "classpath:asserting-party-metadata.xml";
	 *   metadataLocation = "file:asserting-party-metadata.xml";
	 *   metadataLocation = "https://ap.example.org/metadata";
	 * </pre>
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
	 * @param metadataLocation The classpath- or file-based locations or HTTPS endpoints
	 * of the asserting party metadata file
	 * @return the {@link RelyingPartyRegistration.Builder} for further configuration
	 */
	public static RelyingPartyRegistration.Builder fromMetadataLocation(String metadataLocation) {
		try (InputStream source = resourceLoader.getResource(metadataLocation).getInputStream()) {
			return fromMetadata(source);
		}
		catch (IOException ex) {
			if (ex.getCause() instanceof Saml2Exception) {
				throw (Saml2Exception) ex.getCause();
			}
			throw new Saml2Exception(ex);
		}
	}

	/**
	 * Return a {@link RelyingPartyRegistration.Builder} based off of the given SAML 2.0
	 * Asserting Party (IDP) metadata.
	 *
	 * <p>
	 * This method is intended for scenarios when the metadata is looked up by a separate
	 * mechanism. One such example is when the metadata is stored in a database.
	 * </p>
	 *
	 * <p>
	 * <strong>The callers of this method are accountable for closing the
	 * {@code InputStream} source.</strong>
	 * </p>
	 *
	 * Note that by default the registrationId is set to be the given metadata location,
	 * but this will most often not be sufficient. To complete the configuration, most
	 * applications will also need to provide a registrationId, like so:
	 *
	 * <pre>
	 *	String xml = fromDatabase();
	 *	try (InputStream source = new ByteArrayInputStream(xml.getBytes())) {
	 *		RelyingPartyRegistration registration = RelyingPartyRegistrations
	 * 			.fromMetadata(source)
	 * 			.registrationId("registration-id")
	 * 			.build();
	 * 	}
	 * </pre>
	 *
	 * Also note that an {@code IDPSSODescriptor} typically only contains information
	 * about the asserting party. Thus, you will need to remember to still populate
	 * anything about the relying party, like any private keys the relying party will use
	 * for signing AuthnRequests.
	 * @param source the {@link InputStream} source containing the asserting party
	 * metadata
	 * @return the {@link RelyingPartyRegistration.Builder} for further configuration
	 * @since 5.6
	 */
	public static RelyingPartyRegistration.Builder fromMetadata(InputStream source) {
		return collectionFromMetadata(source).iterator().next();
	}

	/**
	 * Return a {@link Collection} of {@link RelyingPartyRegistration.Builder}s based off
	 * of the given SAML 2.0 Asserting Party (IDP) metadata location.
	 *
	 * Valid locations can be classpath- or file-based or they can be HTTPS endpoints.
	 * Some valid endpoints might include:
	 *
	 * <pre>
	 *   metadataLocation = "classpath:asserting-party-metadata.xml";
	 *   metadataLocation = "file:asserting-party-metadata.xml";
	 *   metadataLocation = "https://ap.example.org/metadata";
	 * </pre>
	 *
	 * Note that by default the registrationId is set to be the given metadata location,
	 * but this will most often not be sufficient. To complete the configuration, most
	 * applications will also need to provide a registrationId, like so:
	 *
	 * <pre>
	 *	Iterable&lt;RelyingPartyRegistration&gt; registrations = RelyingPartyRegistrations
	 * 			.collectionFromMetadataLocation(location).iterator();
	 * 	RelyingPartyRegistration one = registrations.next().registrationId("one").build();
	 * 	RelyingPartyRegistration two = registrations.next().registrationId("two").build();
	 * 	return new InMemoryRelyingPartyRegistrationRepository(one, two);
	 * </pre>
	 *
	 * Also note that an {@code IDPSSODescriptor} typically only contains information
	 * about the asserting party. Thus, you will need to remember to still populate
	 * anything about the relying party, like any private keys the relying party will use
	 * for signing AuthnRequests.
	 * @param location The classpath- or file-based locations or HTTPS endpoints of the
	 * asserting party metadata file
	 * @return the {@link Collection} of {@link RelyingPartyRegistration.Builder}s for
	 * further configuration
	 * @since 5.7
	 */
	public static Collection<RelyingPartyRegistration.Builder> collectionFromMetadataLocation(String location) {
		try (InputStream source = resourceLoader.getResource(location).getInputStream()) {
			return collectionFromMetadata(source);
		}
		catch (IOException ex) {
			if (ex.getCause() instanceof Saml2Exception) {
				throw (Saml2Exception) ex.getCause();
			}
			throw new Saml2Exception(ex);
		}
	}

	/**
	 * Return a {@link Collection} of {@link RelyingPartyRegistration.Builder}s based off
	 * of the given SAML 2.0 Asserting Party (IDP) metadata.
	 *
	 * <p>
	 * This method is intended for scenarios when the metadata is looked up by a separate
	 * mechanism. One such example is when the metadata is stored in a database.
	 * </p>
	 *
	 * <p>
	 * <strong>The callers of this method are accountable for closing the
	 * {@code InputStream} source.</strong>
	 * </p>
	 *
	 * Note that by default the registrationId is set to be the given metadata location,
	 * but this will most often not be sufficient. To complete the configuration, most
	 * applications will also need to provide a registrationId, like so:
	 *
	 * <pre>
	 *	String xml = fromDatabase();
	 *	try (InputStream source = new ByteArrayInputStream(xml.getBytes())) {
	 *		Iterator&lt;RelyingPartyRegistration&gt; registrations = RelyingPartyRegistrations
	 * 				.collectionFromMetadata(source).iterator();
	 * 		RelyingPartyRegistration one = registrations.next().registrationId("one").build();
	 * 		RelyingPartyRegistration two = registrations.next().registrationId("two").build();
	 * 		return new InMemoryRelyingPartyRegistrationRepository(one, two);
	 * 	}
	 * </pre>
	 *
	 * Also note that an {@code IDPSSODescriptor} typically only contains information
	 * about the asserting party. Thus, you will need to remember to still populate
	 * anything about the relying party, like any private keys the relying party will use
	 * for signing AuthnRequests.
	 * @param source the {@link InputStream} source containing the asserting party
	 * metadata
	 * @return the {@link Collection} of {@link RelyingPartyRegistration.Builder}s for
	 * further configuration
	 * @since 5.7
	 */
	public static Collection<RelyingPartyRegistration.Builder> collectionFromMetadata(InputStream source) {
		Collection<RelyingPartyRegistration.Builder> builders = new ArrayList<>();
		for (EntityDescriptor descriptor : OpenSamlMetadataUtils.descriptors(source)) {
			if (descriptor.getIDPSSODescriptor(SAMLConstants.SAML20P_NS) != null) {
				OpenSamlAssertingPartyDetails assertingParty = OpenSamlAssertingPartyDetails
					.withEntityDescriptor(descriptor)
					.build();
				builders.add(new OpenSamlRelyingPartyRegistration.Builder(assertingParty));
			}
		}
		if (builders.isEmpty()) {
			throw new Saml2Exception("Metadata response is missing the necessary IDPSSODescriptor element");
		}
		return builders;
	}

}
