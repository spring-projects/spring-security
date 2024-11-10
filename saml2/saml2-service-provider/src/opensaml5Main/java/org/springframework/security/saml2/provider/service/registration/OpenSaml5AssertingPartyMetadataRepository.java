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

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.function.Consumer;

import javax.annotation.Nonnull;

import net.shibboleth.shared.resolver.CriteriaSet;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.criterion.EntityRoleCriterion;
import org.opensaml.saml.metadata.IterableMetadataSource;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.opensaml.saml.metadata.resolver.filter.impl.SignatureValidationFilter;
import org.opensaml.saml.metadata.resolver.impl.ResourceBackedMetadataResolver;
import org.opensaml.saml.metadata.resolver.index.impl.RoleMetadataIndex;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.impl.CollectionCredentialResolver;
import org.opensaml.xmlsec.config.impl.DefaultSecurityConfigurationBootstrap;
import org.opensaml.xmlsec.signature.support.SignatureTrustEngine;
import org.opensaml.xmlsec.signature.support.impl.ExplicitKeySignatureTrustEngine;

import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.core.OpenSamlInitializationService;
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
public final class OpenSaml5AssertingPartyMetadataRepository implements AssertingPartyMetadataRepository {

	static {
		OpenSamlInitializationService.initialize();
	}

	private final BaseOpenSamlAssertingPartyMetadataRepository delegate;

	/**
	 * Construct an {@link OpenSaml5AssertingPartyMetadataRepository} using the provided
	 * {@link MetadataResolver}.
	 *
	 * <p>
	 * The {@link MetadataResolver} should either be of type
	 * {@link IterableMetadataSource} or it should have a {@link RoleMetadataIndex}
	 * configured.
	 * @param metadataResolver the {@link MetadataResolver} to use
	 */
	public OpenSaml5AssertingPartyMetadataRepository(MetadataResolver metadataResolver) {
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
	 * A builder class for configuring {@link OpenSaml5AssertingPartyMetadataRepository}
	 * for a specific metadata location.
	 *
	 * @author Josh Cummings
	 */
	public static final class MetadataLocationRepositoryBuilder {

		private final String metadataLocation;

		private final boolean requireVerificationCredentials;

		private final Collection<Credential> verificationCredentials = new ArrayList<>();

		private ResourceLoader resourceLoader = new DefaultResourceLoader();

		MetadataLocationRepositoryBuilder(String metadataLocation, boolean trusted) {
			this.metadataLocation = metadataLocation;
			this.requireVerificationCredentials = !trusted;
		}

		public MetadataLocationRepositoryBuilder verificationCredentials(Consumer<Collection<Credential>> credentials) {
			credentials.accept(this.verificationCredentials);
			return this;
		}

		public MetadataLocationRepositoryBuilder resourceLoader(ResourceLoader resourceLoader) {
			this.resourceLoader = resourceLoader;
			return this;
		}

		public OpenSaml5AssertingPartyMetadataRepository build() {
			return new OpenSaml5AssertingPartyMetadataRepository(metadataResolver());
		}

		private MetadataResolver metadataResolver() {
			ResourceBackedMetadataResolver metadataResolver = resourceBackedMetadataResolver();
			boolean missingCredentials = this.requireVerificationCredentials && this.verificationCredentials.isEmpty();
			Assert.isTrue(!missingCredentials, "Verification credentials are required");
			return initialize(metadataResolver);
		}

		private ResourceBackedMetadataResolver resourceBackedMetadataResolver() {
			Resource resource = this.resourceLoader.getResource(this.metadataLocation);
			try {
				ResourceBackedMetadataResolver metadataResolver = new ResourceBackedMetadataResolver(
						new SpringResource(resource));
				if (this.verificationCredentials.isEmpty()) {
					return metadataResolver;
				}
				SignatureTrustEngine engine = new ExplicitKeySignatureTrustEngine(
						new CollectionCredentialResolver(this.verificationCredentials),
						DefaultSecurityConfigurationBootstrap.buildBasicInlineKeyInfoCredentialResolver());
				SignatureValidationFilter filter = new SignatureValidationFilter(engine);
				filter.setRequireSignedRoot(true);
				metadataResolver.setMetadataFilter(filter);
				filter.initialize();
				return metadataResolver;
			}
			catch (Exception ex) {
				throw new Saml2Exception(ex);
			}
		}

		private MetadataResolver initialize(ResourceBackedMetadataResolver metadataResolver) {
			metadataResolver.setParserPool(XMLObjectProviderRegistrySupport.getParserPool());
			return BaseOpenSamlAssertingPartyMetadataRepository.initialize(metadataResolver);
		}

		private static final class SpringResource implements net.shibboleth.shared.resource.Resource {

			private final Resource resource;

			SpringResource(Resource resource) {
				this.resource = resource;
			}

			@Override
			public boolean exists() {
				return this.resource.exists();
			}

			@Override
			public boolean isReadable() {
				return this.resource.isReadable();
			}

			@Override
			public boolean isOpen() {
				return this.resource.isOpen();
			}

			@Override
			public URL getURL() throws IOException {
				return this.resource.getURL();
			}

			@Override
			public URI getURI() throws IOException {
				return this.resource.getURI();
			}

			@Override
			public File getFile() throws IOException {
				return this.resource.getFile();
			}

			@Nonnull
			@Override
			public InputStream getInputStream() throws IOException {
				return this.resource.getInputStream();
			}

			@Override
			public long contentLength() throws IOException {
				return this.resource.contentLength();
			}

			@Override
			public long lastModified() throws IOException {
				return this.resource.lastModified();
			}

			@Override
			public net.shibboleth.shared.resource.Resource createRelativeResource(String relativePath)
					throws IOException {
				return new SpringResource(this.resource.createRelative(relativePath));
			}

			@Override
			public String getFilename() {
				return this.resource.getFilename();
			}

			@Override
			public String getDescription() {
				return this.resource.getDescription();
			}

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
