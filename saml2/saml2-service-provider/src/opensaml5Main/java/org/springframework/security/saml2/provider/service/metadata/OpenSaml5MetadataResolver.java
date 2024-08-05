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

import java.util.function.Consumer;

import org.opensaml.saml.saml2.metadata.EntityDescriptor;

import org.springframework.security.saml2.core.OpenSamlInitializationService;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;

/**
 * Resolves the SAML 2.0 Relying Party Metadata for a given
 * {@link RelyingPartyRegistration} using the OpenSAML API.
 *
 * @author Jakub Kubrynski
 * @author Josh Cummings
 * @since 5.4
 */
public final class OpenSaml5MetadataResolver implements Saml2MetadataResolver {

	static {
		OpenSamlInitializationService.initialize();
	}

	private final BaseOpenSamlMetadataResolver delegate;

	public OpenSaml5MetadataResolver() {
		this.delegate = new BaseOpenSamlMetadataResolver(new OpenSaml5Template());
	}

	@Override
	public String resolve(RelyingPartyRegistration relyingPartyRegistration) {
		return this.delegate.resolve(relyingPartyRegistration);
	}

	public String resolve(Iterable<RelyingPartyRegistration> relyingPartyRegistrations) {
		return this.delegate.resolve(relyingPartyRegistrations);
	}

	/**
	 * Set a {@link Consumer} for modifying the OpenSAML {@link EntityDescriptor}
	 * @param entityDescriptorCustomizer a consumer that accepts an
	 * {@link EntityDescriptorParameters}
	 * @since 5.7
	 */
	public void setEntityDescriptorCustomizer(Consumer<EntityDescriptorParameters> entityDescriptorCustomizer) {
		this.delegate.setEntityDescriptorCustomizer(
				(parameters) -> entityDescriptorCustomizer.accept(new EntityDescriptorParameters(parameters)));
	}

	/**
	 * Configure whether to pretty-print the metadata XML. This can be helpful when
	 * signing the metadata payload.
	 *
	 * @since 6.2
	 **/
	public void setUsePrettyPrint(boolean usePrettyPrint) {
		this.delegate.setUsePrettyPrint(usePrettyPrint);
	}

	/**
	 * Configure whether to sign the metadata, defaults to {@code false}.
	 *
	 * @since 6.4
	 */
	public void setSignMetadata(boolean signMetadata) {
		this.delegate.setSignMetadata(signMetadata);
	}

	/**
	 * A tuple containing an OpenSAML {@link EntityDescriptor} and its associated
	 * {@link RelyingPartyRegistration}
	 *
	 * @since 5.7
	 */
	public static final class EntityDescriptorParameters {

		private final EntityDescriptor entityDescriptor;

		private final RelyingPartyRegistration registration;

		public EntityDescriptorParameters(EntityDescriptor entityDescriptor, RelyingPartyRegistration registration) {
			this.entityDescriptor = entityDescriptor;
			this.registration = registration;
		}

		EntityDescriptorParameters(BaseOpenSamlMetadataResolver.EntityDescriptorParameters parameters) {
			this.entityDescriptor = parameters.getEntityDescriptor();
			this.registration = parameters.getRelyingPartyRegistration();
		}

		public EntityDescriptor getEntityDescriptor() {
			return this.entityDescriptor;
		}

		public RelyingPartyRegistration getRelyingPartyRegistration() {
			return this.registration;
		}

	}

}
