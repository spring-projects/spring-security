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

package org.springframework.security.config.http;

import org.w3c.dom.Element;

import org.springframework.beans.BeanMetadataElement;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.util.StringUtils;

/**
 * @author Joe Grandja
 * @since 5.4
 */
final class OAuth2ClientBeanDefinitionParserUtils {

	private static final String ATT_CLIENT_REGISTRATION_REPOSITORY_REF = "client-registration-repository-ref";

	private static final String ATT_AUTHORIZED_CLIENT_REPOSITORY_REF = "authorized-client-repository-ref";

	private static final String ATT_AUTHORIZED_CLIENT_SERVICE_REF = "authorized-client-service-ref";

	private OAuth2ClientBeanDefinitionParserUtils() {
	}

	static BeanMetadataElement getClientRegistrationRepository(Element element) {
		BeanMetadataElement clientRegistrationRepository;
		String clientRegistrationRepositoryRef = element.getAttribute(ATT_CLIENT_REGISTRATION_REPOSITORY_REF);
		if (!StringUtils.isEmpty(clientRegistrationRepositoryRef)) {
			clientRegistrationRepository = new RuntimeBeanReference(clientRegistrationRepositoryRef);
		}
		else {
			clientRegistrationRepository = new RuntimeBeanReference(ClientRegistrationRepository.class);
		}
		return clientRegistrationRepository;
	}

	static BeanMetadataElement getAuthorizedClientRepository(Element element) {
		String authorizedClientRepositoryRef = element.getAttribute(ATT_AUTHORIZED_CLIENT_REPOSITORY_REF);
		if (!StringUtils.isEmpty(authorizedClientRepositoryRef)) {
			return new RuntimeBeanReference(authorizedClientRepositoryRef);
		}
		return null;
	}

	static BeanMetadataElement getAuthorizedClientService(Element element) {
		String authorizedClientServiceRef = element.getAttribute(ATT_AUTHORIZED_CLIENT_SERVICE_REF);
		if (!StringUtils.isEmpty(authorizedClientServiceRef)) {
			return new RuntimeBeanReference(authorizedClientServiceRef);
		}
		return null;
	}

	static BeanDefinition createDefaultAuthorizedClientRepository(BeanMetadataElement clientRegistrationRepository,
			BeanMetadataElement authorizedClientService) {
		if (authorizedClientService == null) {
			authorizedClientService = BeanDefinitionBuilder
					.rootBeanDefinition(
							"org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService")
					.addConstructorArgValue(clientRegistrationRepository).getBeanDefinition();
		}
		return BeanDefinitionBuilder.rootBeanDefinition(
				"org.springframework.security.oauth2.client.web.AuthenticatedPrincipalOAuth2AuthorizedClientRepository")
				.addConstructorArgValue(authorizedClientService).getBeanDefinition();
	}

}
