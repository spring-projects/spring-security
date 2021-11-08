/*
 * Copyright 2002-2022 the original author or authors.
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
import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.HttpSessionSaml2AuthenticationRequestRepository;
import org.springframework.security.saml2.provider.service.web.Saml2AuthenticationTokenConverter;
import org.springframework.util.StringUtils;

/**
 * @author Marcus da Coregio
 * @since 5.7
 */
final class Saml2LoginBeanDefinitionParserUtils {

	private static final String ATT_RELYING_PARTY_REGISTRATION_REPOSITORY_REF = "relying-party-registration-repository-ref";

	private static final String ATT_AUTHENTICATION_REQUEST_REPOSITORY_REF = "authentication-request-repository-ref";

	private static final String ATT_AUTHENTICATION_REQUEST_RESOLVER_REF = "authentication-request-resolver-ref";

	private static final String ATT_AUTHENTICATION_CONVERTER = "authentication-converter-ref";

	private Saml2LoginBeanDefinitionParserUtils() {
	}

	static BeanMetadataElement getRelyingPartyRegistrationRepository(Element element) {
		String relyingPartyRegistrationRepositoryRef = element
				.getAttribute(ATT_RELYING_PARTY_REGISTRATION_REPOSITORY_REF);
		if (StringUtils.hasText(relyingPartyRegistrationRepositoryRef)) {
			return new RuntimeBeanReference(relyingPartyRegistrationRepositoryRef);
		}
		return new RuntimeBeanReference(RelyingPartyRegistrationRepository.class);
	}

	static BeanMetadataElement getAuthenticationRequestRepository(Element element) {
		String authenticationRequestRepositoryRef = element.getAttribute(ATT_AUTHENTICATION_REQUEST_REPOSITORY_REF);
		if (StringUtils.hasText(authenticationRequestRepositoryRef)) {
			return new RuntimeBeanReference(authenticationRequestRepositoryRef);
		}
		return BeanDefinitionBuilder.rootBeanDefinition(HttpSessionSaml2AuthenticationRequestRepository.class)
				.getBeanDefinition();
	}

	static BeanMetadataElement getAuthenticationRequestResolver(Element element) {
		String authenticationRequestContextResolver = element.getAttribute(ATT_AUTHENTICATION_REQUEST_RESOLVER_REF);
		if (StringUtils.hasText(authenticationRequestContextResolver)) {
			return new RuntimeBeanReference(authenticationRequestContextResolver);
		}
		return null;
	}

	static BeanMetadataElement createDefaultAuthenticationRequestResolver(
			BeanMetadataElement relyingPartyRegistrationRepository) {
		BeanMetadataElement defaultRelyingPartyRegistrationResolver = BeanDefinitionBuilder
				.rootBeanDefinition(DefaultRelyingPartyRegistrationResolver.class)
				.addConstructorArgValue(relyingPartyRegistrationRepository).getBeanDefinition();
		return BeanDefinitionBuilder.rootBeanDefinition(
				"org.springframework.security.saml2.provider.service.web.authentication.OpenSaml4AuthenticationRequestResolver")
				.addConstructorArgValue(defaultRelyingPartyRegistrationResolver).getBeanDefinition();
	}

	static BeanDefinition createAuthenticationProvider() {
		return BeanDefinitionBuilder.rootBeanDefinition(
				"org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider")
				.getBeanDefinition();
	}

	static BeanMetadataElement getAuthenticationConverter(Element element) {
		String authenticationConverter = element.getAttribute(ATT_AUTHENTICATION_CONVERTER);
		if (StringUtils.hasText(authenticationConverter)) {
			return new RuntimeBeanReference(authenticationConverter);
		}
		return null;
	}

	static BeanDefinition createDefaultAuthenticationConverter(BeanMetadataElement relyingPartyRegistrationRepository) {
		AbstractBeanDefinition resolver = BeanDefinitionBuilder
				.rootBeanDefinition(DefaultRelyingPartyRegistrationResolver.class)
				.addConstructorArgValue(relyingPartyRegistrationRepository).getBeanDefinition();
		return BeanDefinitionBuilder.rootBeanDefinition(Saml2AuthenticationTokenConverter.class)
				.addConstructorArgValue(resolver).getBeanDefinition();
	}

}
