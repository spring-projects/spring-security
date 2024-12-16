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
import java.util.Set;
import java.util.function.Supplier;

import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.saml.criterion.EntityRoleCriterion;
import org.opensaml.saml.metadata.IterableMetadataSource;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.opensaml.saml.metadata.resolver.impl.AbstractBatchMetadataResolver;
import org.opensaml.saml.metadata.resolver.impl.ResourceBackedMetadataResolver;
import org.opensaml.saml.metadata.resolver.index.MetadataIndex;
import org.opensaml.saml.metadata.resolver.index.impl.RoleMetadataIndex;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;

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

	static MetadataResolver initialize(ResourceBackedMetadataResolver metadataResolver) {
		try {
			metadataResolver.setId(BaseOpenSamlAssertingPartyMetadataRepository.class.getName() + ".metadataResolver");
			metadataResolver.setIndexes(Set.of(new RoleMetadataIndex()));
			metadataResolver.initialize();
			return metadataResolver;
		}
		catch (Exception ex) {
			throw new Saml2Exception(ex);
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
