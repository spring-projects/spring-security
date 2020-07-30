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

package org.springframework.security.config.oauth2.client;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.w3c.dom.Element;

import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.parsing.BeanComponentDefinition;
import org.springframework.beans.factory.parsing.CompositeComponentDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrations;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthenticationMethod;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;

/**
 * @author Ruby Hartono
 * @since 5.3
 */
public final class ClientRegistrationsBeanDefinitionParser implements BeanDefinitionParser {

	private static final String ELT_CLIENT_REGISTRATION = "client-registration";

	private static final String ELT_PROVIDER = "provider";

	private static final String ATT_REGISTRATION_ID = "registration-id";

	private static final String ATT_CLIENT_ID = "client-id";

	private static final String ATT_CLIENT_SECRET = "client-secret";

	private static final String ATT_CLIENT_AUTHENTICATION_METHOD = "client-authentication-method";

	private static final String ATT_AUTHORIZATION_GRANT_TYPE = "authorization-grant-type";

	private static final String ATT_REDIRECT_URI = "redirect-uri";

	private static final String ATT_SCOPE = "scope";

	private static final String ATT_CLIENT_NAME = "client-name";

	private static final String ATT_PROVIDER_ID = "provider-id";

	private static final String ATT_AUTHORIZATION_URI = "authorization-uri";

	private static final String ATT_TOKEN_URI = "token-uri";

	private static final String ATT_USER_INFO_URI = "user-info-uri";

	private static final String ATT_USER_INFO_AUTHENTICATION_METHOD = "user-info-authentication-method";

	private static final String ATT_USER_INFO_USER_NAME_ATTRIBUTE = "user-info-user-name-attribute";

	private static final String ATT_JWK_SET_URI = "jwk-set-uri";

	private static final String ATT_ISSUER_URI = "issuer-uri";

	@Override
	public BeanDefinition parse(Element element, ParserContext parserContext) {
		CompositeComponentDefinition compositeDef = new CompositeComponentDefinition(element.getTagName(),
				parserContext.extractSource(element));
		parserContext.pushContainingComponent(compositeDef);

		Map<String, Map<String, String>> providers = getProviders(element);
		List<ClientRegistration> clientRegistrations = getClientRegistrations(element, parserContext, providers);

		BeanDefinition clientRegistrationRepositoryBean = BeanDefinitionBuilder
				.rootBeanDefinition(InMemoryClientRegistrationRepository.class)
				.addConstructorArgValue(clientRegistrations).getBeanDefinition();
		String clientRegistrationRepositoryId = parserContext.getReaderContext()
				.generateBeanName(clientRegistrationRepositoryBean);
		parserContext.registerBeanComponent(
				new BeanComponentDefinition(clientRegistrationRepositoryBean, clientRegistrationRepositoryId));

		parserContext.popAndRegisterContainingComponent();
		return null;
	}

	private List<ClientRegistration> getClientRegistrations(Element element, ParserContext parserContext,
			Map<String, Map<String, String>> providers) {
		List<Element> clientRegistrationElts = DomUtils.getChildElementsByTagName(element, ELT_CLIENT_REGISTRATION);
		List<ClientRegistration> clientRegistrations = new ArrayList<>();

		for (Element clientRegistrationElt : clientRegistrationElts) {
			String registrationId = clientRegistrationElt.getAttribute(ATT_REGISTRATION_ID);
			String providerId = clientRegistrationElt.getAttribute(ATT_PROVIDER_ID);
			ClientRegistration.Builder builder = getBuilderFromIssuerIfPossible(registrationId, providerId, providers);
			if (builder == null) {
				builder = getBuilder(registrationId, providerId, providers);
				if (builder == null) {
					Object source = parserContext.extractSource(element);
					parserContext.getReaderContext().error(getErrorMessage(providerId, registrationId), source);
					// error on the config skip to next element
					continue;
				}
			}
			getOptionalIfNotEmpty(clientRegistrationElt.getAttribute(ATT_CLIENT_ID)).ifPresent(builder::clientId);
			getOptionalIfNotEmpty(clientRegistrationElt.getAttribute(ATT_CLIENT_SECRET))
					.ifPresent(builder::clientSecret);
			getOptionalIfNotEmpty(clientRegistrationElt.getAttribute(ATT_CLIENT_AUTHENTICATION_METHOD))
					.map(ClientAuthenticationMethod::new).ifPresent(builder::clientAuthenticationMethod);
			getOptionalIfNotEmpty(clientRegistrationElt.getAttribute(ATT_AUTHORIZATION_GRANT_TYPE))
					.map(AuthorizationGrantType::new).ifPresent(builder::authorizationGrantType);
			getOptionalIfNotEmpty(clientRegistrationElt.getAttribute(ATT_REDIRECT_URI)).ifPresent(builder::redirectUri);
			getOptionalIfNotEmpty(clientRegistrationElt.getAttribute(ATT_SCOPE))
					.map(StringUtils::commaDelimitedListToSet).ifPresent(builder::scope);
			getOptionalIfNotEmpty(clientRegistrationElt.getAttribute(ATT_CLIENT_NAME)).ifPresent(builder::clientName);
			clientRegistrations.add(builder.build());
		}

		return clientRegistrations;
	}

	private Map<String, Map<String, String>> getProviders(Element element) {
		List<Element> providerElts = DomUtils.getChildElementsByTagName(element, ELT_PROVIDER);
		Map<String, Map<String, String>> providers = new HashMap<>();

		for (Element providerElt : providerElts) {
			Map<String, String> provider = new HashMap<>();
			String providerId = providerElt.getAttribute(ATT_PROVIDER_ID);
			provider.put(ATT_PROVIDER_ID, providerId);
			getOptionalIfNotEmpty(providerElt.getAttribute(ATT_AUTHORIZATION_URI))
					.ifPresent((value) -> provider.put(ATT_AUTHORIZATION_URI, value));
			getOptionalIfNotEmpty(providerElt.getAttribute(ATT_TOKEN_URI))
					.ifPresent((value) -> provider.put(ATT_TOKEN_URI, value));
			getOptionalIfNotEmpty(providerElt.getAttribute(ATT_USER_INFO_URI))
					.ifPresent((value) -> provider.put(ATT_USER_INFO_URI, value));
			getOptionalIfNotEmpty(providerElt.getAttribute(ATT_USER_INFO_AUTHENTICATION_METHOD))
					.ifPresent((value) -> provider.put(ATT_USER_INFO_AUTHENTICATION_METHOD, value));
			getOptionalIfNotEmpty(providerElt.getAttribute(ATT_USER_INFO_USER_NAME_ATTRIBUTE))
					.ifPresent((value) -> provider.put(ATT_USER_INFO_USER_NAME_ATTRIBUTE, value));
			getOptionalIfNotEmpty(providerElt.getAttribute(ATT_JWK_SET_URI))
					.ifPresent((value) -> provider.put(ATT_JWK_SET_URI, value));
			getOptionalIfNotEmpty(providerElt.getAttribute(ATT_ISSUER_URI))
					.ifPresent((value) -> provider.put(ATT_ISSUER_URI, value));
			providers.put(providerId, provider);
		}

		return providers;
	}

	private static ClientRegistration.Builder getBuilderFromIssuerIfPossible(String registrationId,
			String configuredProviderId, Map<String, Map<String, String>> providers) {
		String providerId = configuredProviderId != null ? configuredProviderId : registrationId;
		if (providers.containsKey(providerId)) {
			Map<String, String> provider = providers.get(providerId);
			String issuer = provider.get(ATT_ISSUER_URI);
			if (!StringUtils.isEmpty(issuer)) {
				ClientRegistration.Builder builder = ClientRegistrations.fromIssuerLocation(issuer)
						.registrationId(registrationId);
				return getBuilder(builder, provider);
			}
		}
		return null;
	}

	private static ClientRegistration.Builder getBuilder(String registrationId, String configuredProviderId,
			Map<String, Map<String, String>> providers) {
		String providerId = (configuredProviderId != null) ? configuredProviderId : registrationId;
		CommonOAuth2Provider provider = getCommonProvider(providerId);
		if (provider == null && !providers.containsKey(providerId)) {
			return null;
		}
		ClientRegistration.Builder builder = provider != null ? provider.getBuilder(registrationId)
				: ClientRegistration.withRegistrationId(registrationId);
		if (providers.containsKey(providerId)) {
			return getBuilder(builder, providers.get(providerId));
		}
		return builder;
	}

	private static ClientRegistration.Builder getBuilder(ClientRegistration.Builder builder,
			Map<String, String> provider) {
		getOptionalIfNotEmpty(provider.get(ATT_AUTHORIZATION_URI)).ifPresent(builder::authorizationUri);
		getOptionalIfNotEmpty(provider.get(ATT_TOKEN_URI)).ifPresent(builder::tokenUri);
		getOptionalIfNotEmpty(provider.get(ATT_USER_INFO_URI)).ifPresent(builder::userInfoUri);
		getOptionalIfNotEmpty(provider.get(ATT_USER_INFO_AUTHENTICATION_METHOD)).map(AuthenticationMethod::new)
				.ifPresent(builder::userInfoAuthenticationMethod);
		getOptionalIfNotEmpty(provider.get(ATT_JWK_SET_URI)).ifPresent(builder::jwkSetUri);
		getOptionalIfNotEmpty(provider.get(ATT_USER_INFO_USER_NAME_ATTRIBUTE))
				.ifPresent(builder::userNameAttributeName);
		return builder;
	}

	private static Optional<String> getOptionalIfNotEmpty(String str) {
		return Optional.ofNullable(str).filter((s) -> !s.isEmpty());
	}

	private static CommonOAuth2Provider getCommonProvider(String providerId) {
		try {
			String value = providerId.trim();
			if (value.isEmpty()) {
				return null;
			}
			try {
				return CommonOAuth2Provider.valueOf(value);
			}
			catch (Exception ex) {
				return findEnum(value);
			}
		}
		catch (Exception ex) {
			return null;
		}
	}

	private static CommonOAuth2Provider findEnum(String value) {
		String name = getCanonicalName(value);
		for (CommonOAuth2Provider candidate : EnumSet.allOf(CommonOAuth2Provider.class)) {
			String candidateName = getCanonicalName(candidate.name());
			if (name.equals(candidateName)) {
				return candidate;
			}
		}
		throw new IllegalArgumentException(
				"No enum constant " + CommonOAuth2Provider.class.getCanonicalName() + "." + value);
	}

	private static String getCanonicalName(String name) {
		StringBuilder canonicalName = new StringBuilder(name.length());
		name.chars().filter(Character::isLetterOrDigit).map(Character::toLowerCase)
				.forEach((c) -> canonicalName.append((char) c));
		return canonicalName.toString();
	}

	private static String getErrorMessage(String configuredProviderId, String registrationId) {
		return configuredProviderId != null ? "Unknown provider ID '" + configuredProviderId + "'"
				: "Provider ID must be specified for client registration '" + registrationId + "'";
	}

}
