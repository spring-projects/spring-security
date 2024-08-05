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
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.Supplier;

import javax.annotation.Nonnull;

import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.criterion.EntityRoleCriterion;
import org.opensaml.saml.metadata.IterableMetadataSource;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.opensaml.saml.metadata.resolver.filter.impl.SignatureValidationFilter;
import org.opensaml.saml.metadata.resolver.impl.AbstractBatchMetadataResolver;
import org.opensaml.saml.metadata.resolver.impl.ResourceBackedMetadataResolver;
import org.opensaml.saml.metadata.resolver.index.MetadataIndex;
import org.opensaml.saml.metadata.resolver.index.impl.RoleMetadataIndex;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
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
import org.springframework.util.Assert;

class BaseOpenSamlAssertingPartyMetadataRepository implements AssertingPartyMetadataRepository {

	static {
		OpenSamlInitializationService.initialize();
	}

	private final MetadataResolverAdapter metadataResolver;

	private final Supplier<Iterator<EntityDescriptor>> descriptors;

	/**
	 * Construct an {@link BaseOpenSamlAssertingPartyMetadataRepository} using the
	 * provided {@link MetadataResolver}.
	 *
	 * <p>
	 * The {@link MetadataResolver} should either be of type
	 * {@link IterableMetadataSource} or it should have a {@link RoleMetadataIndex}
	 * configured.
	 * @param metadataResolver the {@link MetadataResolver} to use
	 */
	BaseOpenSamlAssertingPartyMetadataRepository(MetadataResolverAdapter metadataResolver) {
		Assert.notNull(metadataResolver, "metadataResolver cannot be null");
		if (isRoleIndexed(metadataResolver.metadataResolver)) {
			this.descriptors = this::allIndexedEntities;
		}
		else if (metadataResolver.metadataResolver instanceof IterableMetadataSource source) {
			this.descriptors = source::iterator;
		}
		else {
			throw new IllegalArgumentException(
					"metadataResolver must be an IterableMetadataSource or have a RoleMetadataIndex");
		}
		this.metadataResolver = metadataResolver;
	}

	private static boolean isRoleIndexed(MetadataResolver resolver) {
		if (!(resolver instanceof AbstractBatchMetadataResolver batch)) {
			return false;
		}
		for (MetadataIndex index : batch.getIndexes()) {
			if (index instanceof RoleMetadataIndex) {
				return true;
			}
		}
		return false;
	}

	private Iterator<EntityDescriptor> allIndexedEntities() {
		EntityRoleCriterion idps = new EntityRoleCriterion(IDPSSODescriptor.DEFAULT_ELEMENT_NAME);
		try {
			return this.metadataResolver.resolve(idps).iterator();
		}
		catch (Exception ex) {
			throw new Saml2Exception(ex);
		}
	}

	@Override
	@NonNull
	public Iterator<AssertingPartyMetadata> iterator() {
		Iterator<EntityDescriptor> descriptors = this.descriptors.get();
		return new Iterator<>() {
			@Override
			public boolean hasNext() {
				return descriptors.hasNext();
			}

			@Override
			public AssertingPartyMetadata next() {
				return OpenSamlAssertingPartyDetails.withEntityDescriptor(descriptors.next()).build();
			}
		};
	}

	@Nullable
	@Override
	public AssertingPartyMetadata findByEntityId(String entityId) {
		EntityDescriptor descriptor = resolveSingle(new EntityIdCriterion(entityId));
		if (descriptor == null) {
			return null;
		}
		return OpenSamlAssertingPartyDetails.withEntityDescriptor(descriptor).build();
	}

	private EntityDescriptor resolveSingle(EntityIdCriterion criterion) {
		try {
			return this.metadataResolver.resolveSingle(criterion);
		}
		catch (Exception ex) {
			throw new Saml2Exception(ex);
		}
	}

	/**
	 * A builder class for configuring
	 * {@link BaseOpenSamlAssertingPartyMetadataRepository} for a specific metadata
	 * location.
	 *
	 * @author Josh Cummings
	 */
	static final class MetadataLocationRepositoryBuilder {

		private final String metadataLocation;

		private final boolean requireVerificationCredentials;

		private final Collection<Credential> verificationCredentials = new ArrayList<>();

		private ResourceLoader resourceLoader = new DefaultResourceLoader();

		MetadataLocationRepositoryBuilder(String metadataLocation, boolean trusted) {
			this.metadataLocation = metadataLocation;
			this.requireVerificationCredentials = !trusted;
		}

		MetadataLocationRepositoryBuilder verificationCredentials(Consumer<Collection<Credential>> credentials) {
			credentials.accept(this.verificationCredentials);
			return this;
		}

		MetadataLocationRepositoryBuilder resourceLoader(ResourceLoader resourceLoader) {
			this.resourceLoader = resourceLoader;
			return this;
		}

		MetadataResolver metadataResolver() {
			ResourceBackedMetadataResolver metadataResolver = resourceBackedMetadataResolver();
			if (!this.verificationCredentials.isEmpty()) {
				SignatureTrustEngine engine = new ExplicitKeySignatureTrustEngine(
						new CollectionCredentialResolver(this.verificationCredentials),
						DefaultSecurityConfigurationBootstrap.buildBasicInlineKeyInfoCredentialResolver());
				SignatureValidationFilter filter = new SignatureValidationFilter(engine);
				filter.setRequireSignedRoot(true);
				metadataResolver.setMetadataFilter(filter);
				return initialize(metadataResolver);
			}
			Assert.isTrue(!this.requireVerificationCredentials, "Verification credentials are required");
			return initialize(metadataResolver);
		}

		private ResourceBackedMetadataResolver resourceBackedMetadataResolver() {
			Resource resource = this.resourceLoader.getResource(this.metadataLocation);
			try {
				return new ResourceBackedMetadataResolver(new SpringResource(resource));
			}
			catch (IOException ex) {
				throw new Saml2Exception(ex);
			}
		}

		private MetadataResolver initialize(ResourceBackedMetadataResolver metadataResolver) {
			try {
				metadataResolver.setId(this.getClass().getName() + ".metadataResolver");
				metadataResolver.setParserPool(XMLObjectProviderRegistrySupport.getParserPool());
				metadataResolver.setIndexes(Set.of(new RoleMetadataIndex()));
				metadataResolver.initialize();
				return metadataResolver;
			}
			catch (Exception ex) {
				throw new Saml2Exception(ex);
			}
		}

		private static final class SpringResource implements net.shibboleth.utilities.java.support.resource.Resource {

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
			public net.shibboleth.utilities.java.support.resource.Resource createRelativeResource(String relativePath)
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

	abstract static class MetadataResolverAdapter {

		final MetadataResolver metadataResolver;

		MetadataResolverAdapter(MetadataResolver metadataResolver) {
			this.metadataResolver = metadataResolver;
		}

		abstract EntityDescriptor resolveSingle(EntityIdCriterion entityId) throws Exception;

		abstract Iterable<EntityDescriptor> resolve(EntityRoleCriterion role) throws Exception;

	}

}
