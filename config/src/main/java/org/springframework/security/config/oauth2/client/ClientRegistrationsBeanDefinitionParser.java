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
import java.util.Set;

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
import org.w3c.dom.Element;

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
	private static final String ATT_USERINFO_URI = "userinfo-uri";
	private static final String ATT_USERINFO_AUTHENTICATION_METHOD = "userinfo-authentication-method";
	private static final String ATT_USERNAME_ATTRIBUTE_NAME = "username-attribute-name";
	private static final String ATT_JWKSET_URI = "jwkset-uri";
	private static final String ATT_ISSUER_URI = "issuer-uri";

	@Override
	public BeanDefinition parse(Element element, ParserContext parserContext) {
		CompositeComponentDefinition compositeDef = new CompositeComponentDefinition(element.getTagName(),
				parserContext.extractSource(element));
		parserContext.pushContainingComponent(compositeDef);

		Map<String, Map<String, String>> providerDetailMap = getProviders(element);

		List<ClientRegistration> clientRegs = getClientRegistrations(element, parserContext, providerDetailMap);

		BeanDefinition inMemClientRegRepoBeanDef = BeanDefinitionBuilder
				.rootBeanDefinition(InMemoryClientRegistrationRepository.class).addConstructorArgValue(clientRegs)
				.getBeanDefinition();
		String beanName = parserContext.getReaderContext().generateBeanName(inMemClientRegRepoBeanDef);
		parserContext.registerBeanComponent(new BeanComponentDefinition(inMemClientRegRepoBeanDef, beanName));

		parserContext.popAndRegisterContainingComponent();
		return null;
	}

	private List<ClientRegistration> getClientRegistrations(Element element, ParserContext parserContext,
			Map<String, Map<String, String>> providerDetailMap) {
		List<Element> clientRegElts = DomUtils.getChildElementsByTagName(element, ELT_CLIENT_REGISTRATION);
		List<ClientRegistration> clientRegs = new ArrayList<>();

		for (Element clientRegElt : clientRegElts) {
			String regId = clientRegElt.getAttribute(ATT_REGISTRATION_ID);
			String clientId = clientRegElt.getAttribute(ATT_CLIENT_ID);
			String clientSecret = clientRegElt.getAttribute(ATT_CLIENT_SECRET);
			String clientAuthMethod = clientRegElt.getAttribute(ATT_CLIENT_AUTHENTICATION_METHOD);
			String authGrantType = clientRegElt.getAttribute(ATT_AUTHORIZATION_GRANT_TYPE);
			String redirectUri = clientRegElt.getAttribute(ATT_REDIRECT_URI);
			String scope = clientRegElt.getAttribute(ATT_SCOPE);
			String clientName = clientRegElt.getAttribute(ATT_CLIENT_NAME);
			String providerId = clientRegElt.getAttribute(ATT_PROVIDER_ID);

			Set<String> scopes = StringUtils.commaDelimitedListToSet(scope);
			ClientRegistration.Builder builder = getBuilderFromIssuerIfPossible(regId, providerId, providerDetailMap);
			if (builder == null) {
				builder = getBuilder(regId, providerId, providerDetailMap);
				if (builder == null) {
					Object source = parserContext.extractSource(element);
					parserContext.getReaderContext().error(getErrorMessage(providerId, regId), source);
					// error on the config skip to next element
					break;
				}
			}

			ClientRegistration clientReg = builder.clientId(clientId)
					.clientSecret(clientSecret)
					.clientAuthenticationMethod(new ClientAuthenticationMethod(clientAuthMethod))
					.authorizationGrantType(new AuthorizationGrantType(authGrantType))
					.redirectUriTemplate(redirectUri)
					.scope(scopes)
					.clientName(clientName)
					.build();
			clientRegs.add(clientReg);
		}
		return clientRegs;
	}

	private Map<String, Map<String, String>> getProviders(Element element) {
		List<Element> providerRegElts = DomUtils.getChildElementsByTagName(element, ELT_PROVIDER);
		Map<String, Map<String, String>> providerDetailMap = new HashMap<>();
		for (Element providerRegElt : providerRegElts) {
			Map<String, String> detail = new HashMap<String, String>();
			String providerId = providerRegElt.getAttribute(ATT_PROVIDER_ID);
			detail.put(ATT_PROVIDER_ID, providerId);
			detail.put(ATT_AUTHORIZATION_URI, providerRegElt.getAttribute(ATT_AUTHORIZATION_URI));
			detail.put(ATT_TOKEN_URI, providerRegElt.getAttribute(ATT_TOKEN_URI));
			detail.put(ATT_USERINFO_URI, providerRegElt.getAttribute(ATT_USERINFO_URI));
			detail.put(ATT_USERINFO_AUTHENTICATION_METHOD,
					providerRegElt.getAttribute(ATT_USERINFO_AUTHENTICATION_METHOD));
			detail.put(ATT_USERNAME_ATTRIBUTE_NAME, providerRegElt.getAttribute(ATT_USERNAME_ATTRIBUTE_NAME));
			detail.put(ATT_JWKSET_URI, providerRegElt.getAttribute(ATT_JWKSET_URI));
			detail.put(ATT_ISSUER_URI, providerRegElt.getAttribute(ATT_ISSUER_URI));

			providerDetailMap.put(providerId, detail);
		}
		return providerDetailMap;
	}

	private static ClientRegistration.Builder getBuilderFromIssuerIfPossible(String registrationId,
			String configuredProviderId, Map<String, Map<String, String>> providers) {
		String providerId = (configuredProviderId != null) ? configuredProviderId : registrationId;
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
		ClientRegistration.Builder builder = (provider != null) ? provider.getBuilder(registrationId)
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
		getOptionalIfNotEmpty(provider.get(ATT_USERINFO_URI)).ifPresent(builder::userInfoUri);
		getOptionalIfNotEmpty(provider.get(ATT_USERINFO_AUTHENTICATION_METHOD)).map(AuthenticationMethod::new)
				.ifPresent(builder::userInfoAuthenticationMethod);
		getOptionalIfNotEmpty(provider.get(ATT_JWKSET_URI)).ifPresent(builder::jwkSetUri);
		getOptionalIfNotEmpty(provider.get(ATT_USERNAME_ATTRIBUTE_NAME)).ifPresent(builder::userNameAttributeName);
		return builder;
	}

	private static Optional<String> getOptionalIfNotEmpty(String str) {
		return Optional.ofNullable(str).filter(s -> !s.isEmpty());
	}

	private static CommonOAuth2Provider getCommonProvider(String providerId) {
		try {
			String value = providerId.toString().trim();
			if (value.isEmpty()) {
				return null;
			}
			try {
				return CommonOAuth2Provider.valueOf(value);
			} catch (Exception ex) {
				return findEnum(value);
			}
		} catch (Exception ex) {
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
		return ((configuredProviderId != null) ? "Unknown provider ID '" + configuredProviderId + "'"
				: "Provider ID must be specified for client registration '" + registrationId + "'");
	}
}
