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

import java.io.InputStream;
import java.util.Collection;
import java.util.Collections;

import org.opensaml.core.Version;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.saml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.core.OpenSamlInitializationService;

final class OpenSamlMetadataUtils {

	private static final OpenSamlDeserializer saml;

	static {
		OpenSamlInitializationService.initialize();
		saml = resolveDeserializer();
	}

	static OpenSamlDeserializer resolveDeserializer() {
		if (Version.getVersion().startsWith("4")) {
			return new OpenSaml4Deserializer();
		}
		String opensaml5 = "org.springframework.security.saml2.provider.service.registration.OpenSaml5Template";
		try {
			Class<?> template = Class.forName(opensaml5);
			OpenSamlOperations operations = (OpenSamlOperations) template.getDeclaredConstructor().newInstance();
			return operations::deserialize;
		}
		catch (Exception ex) {
			throw new IllegalStateException(
					"Application appears to be using OpenSAML 5, but Spring's OpenSAML 5 support is not on the classpath");
		}
	}

	private OpenSamlMetadataUtils() {

	}

	static Collection<EntityDescriptor> descriptors(InputStream metadata) {
		XMLObject object = saml.deserialize(metadata);
		if (object instanceof EntityDescriptor descriptor) {
			return Collections.singleton(descriptor);
		}
		if (object instanceof EntitiesDescriptor descriptors) {
			return descriptors.getEntityDescriptors();
		}
		throw new Saml2Exception("Unsupported element type: " + object.getClass().getName());
	}

	private interface OpenSamlDeserializer {

		XMLObject deserialize(InputStream serialized);

	}

	private static class OpenSaml4Deserializer implements OpenSamlDeserializer {

		@Override
		public XMLObject deserialize(InputStream serialized) {
			try {
				Document document = XMLObjectProviderRegistrySupport.getParserPool().parse(serialized);
				Element element = document.getDocumentElement();
				UnmarshallerFactory factory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
				Unmarshaller unmarshaller = factory.getUnmarshaller(element);
				if (unmarshaller == null) {
					throw new Saml2Exception("Unsupported element of type " + element.getTagName());
				}
				return unmarshaller.unmarshall(element);
			}
			catch (Saml2Exception ex) {
				throw ex;
			}
			catch (Exception ex) {
				throw new Saml2Exception("Failed to deserialize payload", ex);
			}
		}

	}

}
