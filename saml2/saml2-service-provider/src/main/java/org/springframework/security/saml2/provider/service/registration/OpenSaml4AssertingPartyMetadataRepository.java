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

import java.util.Collection;
import java.util.Iterator;
import java.util.function.Consumer;

import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.saml.criterion.EntityRoleCriterion;
import org.opensaml.saml.metadata.IterableMetadataSource;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.opensaml.saml.metadata.resolver.index.impl.RoleMetadataIndex;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.security.credential.Credential;

import org.springframework.core.io.ResourceLoader;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.BaseOpenSamlAssertingPartyMetadataRepository.MetadataResolverAdapter;
import org.springframework.util.Assert;

/**
 * An implementation of {@link AssertingPartyMetadataRepository} that uses a
 * {@link MetadataResolver} to retrieve {@link AssertingPartyMetadata} instances.
 *
 * <p>
 * The {@link MetadataResolver} constructed in {@link #withTrustedMetadataLocation}
 * provides expiry-aware refreshing.
 *
 * @author Josh Cummings
 * @since 6.4
 * @see AssertingPartyMetadataRepository
 * @see RelyingPartyRegistrations
 */
public final class OpenSaml4AssertingPartyMetadataRepository implements AssertingPartyMetadataRepository {

	private final BaseOpenSamlAssertingPartyMetadataRepository delegate;

	/**
	 * Construct an {@link OpenSaml4AssertingPartyMetadataRepository} using the provided
	 * {@link MetadataResolver}.
	 *
	 * <p>
	 * The {@link MetadataResolver} should either be of type
	 * {@link IterableMetadataSource} or it should have a {@link RoleMetadataIndex}
	 * configured.
	 * @param metadataResolver the {@link MetadataResolver} to use
	 */
	public OpenSaml4AssertingPartyMetadataRepository(MetadataResolver metadataResolver) {
		Assert.notNull(metadataResolver, "metadataResolver cannot be null");
		this.delegate = new BaseOpenSamlAssertingPartyMetadataRepository(
				new CriteriaSetResolverWrapper(metadataResolver));
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	@NonNull
	public Iterator<AssertingPartyMetadata> iterator() {
		return this.delegate.iterator();
	}

	/**
	 * {@inheritDoc}
	 */
	@Nullable
	@Override
	public AssertingPartyMetadata findByEntityId(String entityId) {
		return this.delegate.findByEntityId(entityId);
	}

	/**
	 * Use this trusted {@code metadataLocation} to retrieve refreshable, expiry-aware
	 * SAML 2.0 Asserting Party (IDP) metadata.
	 *
	 * <p>
	 * Valid locations can be classpath- or file-based or they can be HTTPS endpoints.
	 * Some valid endpoints might include:
	 *
	 * <pre>
	 *   metadataLocation = "classpath:asserting-party-metadata.xml";
	 *   metadataLocation = "file:asserting-party-metadata.xml";
	 *   metadataLocation = "https://ap.example.org/metadata";
	 * </pre>
	 *
	 * <p>
	 * Resolution of location is attempted immediately. To defer, wrap in
	 * {@link CachingRelyingPartyRegistrationRepository}.
	 * @param metadataLocation the classpath- or file-based locations or HTTPS endpoints
	 * of the asserting party metadata file
	 * @return the {@link MetadataLocationRepositoryBuilder} for further configuration
	 */
	public static MetadataLocationRepositoryBuilder withTrustedMetadataLocation(String metadataLocation) {
		return new MetadataLocationRepositoryBuilder(metadataLocation, true);
	}

	/**
	 * Use this {@code metadataLocation} to retrieve refreshable, expiry-aware SAML 2.0
	 * Asserting Party (IDP) metadata. Verification credentials are required.
	 *
	 * <p>
	 * Valid locations can be classpath- or file-based or they can be remote endpoints.
	 * Some valid endpoints might include:
	 *
	 * <pre>
	 *   metadataLocation = "classpath:asserting-party-metadata.xml";
	 *   metadataLocation = "file:asserting-party-metadata.xml";
	 *   metadataLocation = "https://ap.example.org/metadata";
	 * </pre>
	 *
	 * <p>
	 * Resolution of location is attempted immediately. To defer, wrap in
	 * {@link CachingRelyingPartyRegistrationRepository}.
	 * @param metadataLocation the classpath- or file-based locations or remote endpoints
	 * of the asserting party metadata file
	 * @return the {@link MetadataLocationRepositoryBuilder} for further configuration
	 */
	public static MetadataLocationRepositoryBuilder withMetadataLocation(String metadataLocation) {
		return new MetadataLocationRepositoryBuilder(metadataLocation, false);
	}

	/**
	 * A builder class for configuring {@link OpenSaml4AssertingPartyMetadataRepository}
	 * for a specific metadata location.
	 *
	 * @author Josh Cummings
	 */
	public static final class MetadataLocationRepositoryBuilder {

		private final BaseOpenSamlAssertingPartyMetadataRepository.MetadataLocationRepositoryBuilder builder;

		MetadataLocationRepositoryBuilder(String metadataLocation, boolean trusted) {
			this.builder = new BaseOpenSamlAssertingPartyMetadataRepository.MetadataLocationRepositoryBuilder(
					metadataLocation, trusted);
		}

		/**
		 * Apply this {@link Consumer} to the list of {@link Saml2X509Credential}s to use
		 * for verifying metadata signatures.
		 *
		 * <p>
		 * If no credentials are supplied, no signature verification is performed.
		 * @param credentials a {@link Consumer} of the {@link Collection} of
		 * {@link Saml2X509Credential}s
		 * @return the
		 * {@link BaseOpenSamlAssertingPartyMetadataRepository.MetadataLocationRepositoryBuilder}
		 * for further configuration
		 */
		public MetadataLocationRepositoryBuilder verificationCredentials(Consumer<Collection<Credential>> credentials) {
			this.builder.verificationCredentials(credentials);
			return this;
		}

		/**
		 * Use this {@link ResourceLoader} for resolving the {@code metadataLocation}
		 * @param resourceLoader the {@link ResourceLoader} to use
		 * @return the
		 * {@link BaseOpenSamlAssertingPartyMetadataRepository.MetadataLocationRepositoryBuilder}
		 * for further configuration
		 */
		public MetadataLocationRepositoryBuilder resourceLoader(ResourceLoader resourceLoader) {
			this.builder.resourceLoader(resourceLoader);
			return this;
		}

		/**
		 * Build the {@link OpenSaml4AssertingPartyMetadataRepository}
		 * @return the {@link OpenSaml4AssertingPartyMetadataRepository}
		 */
		public OpenSaml4AssertingPartyMetadataRepository build() {
			return new OpenSaml4AssertingPartyMetadataRepository(this.builder.metadataResolver());
		}

	}

	private static final class CriteriaSetResolverWrapper extends MetadataResolverAdapter {

		CriteriaSetResolverWrapper(MetadataResolver metadataResolver) {
			super(metadataResolver);
		}

		@Override
		EntityDescriptor resolveSingle(EntityIdCriterion entityId) throws Exception {
			return super.metadataResolver.resolveSingle(new CriteriaSet(entityId));
		}

		@Override
		Iterable<EntityDescriptor> resolve(EntityRoleCriterion role) throws Exception {
			return super.metadataResolver.resolve(new CriteriaSet(role));
		}

	}

}
