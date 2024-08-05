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

import org.opensaml.core.Version;
import org.w3c.dom.Element;

import org.springframework.beans.BeanMetadataElement;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.security.saml2.provider.service.authentication.logout.OpenSaml4LogoutRequestValidator;
import org.springframework.security.saml2.provider.service.authentication.logout.OpenSaml4LogoutResponseValidator;
import org.springframework.security.saml2.provider.service.authentication.logout.OpenSaml5LogoutRequestValidator;
import org.springframework.security.saml2.provider.service.authentication.logout.OpenSaml5LogoutResponseValidator;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.web.authentication.logout.HttpSessionLogoutRequestRepository;
import org.springframework.security.saml2.provider.service.web.authentication.logout.OpenSaml4LogoutRequestResolver;
import org.springframework.security.saml2.provider.service.web.authentication.logout.OpenSaml4LogoutResponseResolver;
import org.springframework.security.saml2.provider.service.web.authentication.logout.OpenSaml5LogoutRequestResolver;
import org.springframework.security.saml2.provider.service.web.authentication.logout.OpenSaml5LogoutResponseResolver;
import org.springframework.util.StringUtils;

/**
 * @author Marcus da Coregio
 * @since 5.7
 */
final class Saml2LogoutBeanDefinitionParserUtils {

	private static final boolean USE_OPENSAML_5 = Version.getVersion().startsWith("5");

	private static final String ATT_RELYING_PARTY_REGISTRATION_REPOSITORY_REF = "relying-party-registration-repository-ref";

	private static final String ATT_LOGOUT_REQUEST_VALIDATOR_REF = "logout-request-validator-ref";

	private static final String ATT_LOGOUT_REQUEST_REPOSITORY_REF = "logout-request-repository-ref";

	private static final String ATT_LOGOUT_REQUEST_RESOLVER_REF = "logout-request-resolver-ref";

	private static final String ATT_LOGOUT_RESPONSE_RESOLVER_REF = "logout-response-resolver-ref";

	private static final String ATT_LOGOUT_RESPONSE_VALIDATOR_REF = "logout-response-validator-ref";

	private Saml2LogoutBeanDefinitionParserUtils() {
	}

	static BeanMetadataElement getRelyingPartyRegistrationRepository(Element element) {
		String relyingPartyRegistrationRepositoryRef = element
			.getAttribute(ATT_RELYING_PARTY_REGISTRATION_REPOSITORY_REF);
		if (StringUtils.hasText(relyingPartyRegistrationRepositoryRef)) {
			return new RuntimeBeanReference(relyingPartyRegistrationRepositoryRef);
		}
		return new RuntimeBeanReference(RelyingPartyRegistrationRepository.class);
	}

	static BeanMetadataElement getLogoutResponseResolver(Element element, BeanMetadataElement registrations) {
		String logoutResponseResolver = element.getAttribute(ATT_LOGOUT_RESPONSE_RESOLVER_REF);
		if (StringUtils.hasText(logoutResponseResolver)) {
			return new RuntimeBeanReference(logoutResponseResolver);
		}
		if (USE_OPENSAML_5) {
			return BeanDefinitionBuilder.rootBeanDefinition(OpenSaml5LogoutResponseResolver.class)
				.addConstructorArgValue(registrations)
				.getBeanDefinition();
		}
		return BeanDefinitionBuilder.rootBeanDefinition(OpenSaml4LogoutResponseResolver.class)
			.addConstructorArgValue(registrations)
			.getBeanDefinition();
	}

	static BeanMetadataElement getLogoutRequestValidator(Element element) {
		String logoutRequestValidator = element.getAttribute(ATT_LOGOUT_REQUEST_VALIDATOR_REF);
		if (StringUtils.hasText(logoutRequestValidator)) {
			return new RuntimeBeanReference(logoutRequestValidator);
		}
		if (USE_OPENSAML_5) {
			return BeanDefinitionBuilder.rootBeanDefinition(OpenSaml5LogoutRequestValidator.class).getBeanDefinition();
		}
		return BeanDefinitionBuilder.rootBeanDefinition(OpenSaml4LogoutRequestValidator.class).getBeanDefinition();
	}

	static BeanMetadataElement getLogoutResponseValidator(Element element) {
		String logoutResponseValidator = element.getAttribute(ATT_LOGOUT_RESPONSE_VALIDATOR_REF);
		if (StringUtils.hasText(logoutResponseValidator)) {
			return new RuntimeBeanReference(logoutResponseValidator);
		}
		if (USE_OPENSAML_5) {
			return BeanDefinitionBuilder.rootBeanDefinition(OpenSaml5LogoutResponseValidator.class).getBeanDefinition();
		}
		return BeanDefinitionBuilder.rootBeanDefinition(OpenSaml4LogoutResponseValidator.class).getBeanDefinition();
	}

	static BeanMetadataElement getLogoutRequestRepository(Element element) {
		String logoutRequestRepository = element.getAttribute(ATT_LOGOUT_REQUEST_REPOSITORY_REF);
		if (StringUtils.hasText(logoutRequestRepository)) {
			return new RuntimeBeanReference(logoutRequestRepository);
		}
		return BeanDefinitionBuilder.rootBeanDefinition(HttpSessionLogoutRequestRepository.class).getBeanDefinition();
	}

	static BeanMetadataElement getLogoutRequestResolver(Element element, BeanMetadataElement registrations) {
		String logoutRequestResolver = element.getAttribute(ATT_LOGOUT_REQUEST_RESOLVER_REF);
		if (StringUtils.hasText(logoutRequestResolver)) {
			return new RuntimeBeanReference(logoutRequestResolver);
		}
		if (USE_OPENSAML_5) {
			return BeanDefinitionBuilder.rootBeanDefinition(OpenSaml5LogoutRequestResolver.class)
				.addConstructorArgValue(registrations)
				.getBeanDefinition();
		}
		return BeanDefinitionBuilder.rootBeanDefinition(OpenSaml4LogoutRequestResolver.class)
			.addConstructorArgValue(registrations)
			.getBeanDefinition();
	}

}
