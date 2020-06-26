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

import org.springframework.beans.BeanMetadataElement;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.BeanReference;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthorizationCodeAuthenticationProvider;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationCodeGrantFilter;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;
import org.w3c.dom.Element;

import static org.springframework.security.config.http.OAuth2ClientBeanDefinitionParserUtils.createAuthorizedClientRepository;
import static org.springframework.security.config.http.OAuth2ClientBeanDefinitionParserUtils.createDefaultAuthorizedClientRepository;
import static org.springframework.security.config.http.OAuth2ClientBeanDefinitionParserUtils.getAuthorizedClientRepository;
import static org.springframework.security.config.http.OAuth2ClientBeanDefinitionParserUtils.getAuthorizedClientService;
import static org.springframework.security.config.http.OAuth2ClientBeanDefinitionParserUtils.getClientRegistrationRepository;

/**
 * @author Joe Grandja
 * @since 5.3
 */
final class OAuth2ClientBeanDefinitionParser implements BeanDefinitionParser {
	private static final String ELT_AUTHORIZATION_CODE_GRANT = "authorization-code-grant";
	private static final String ATT_AUTHORIZATION_REQUEST_REPOSITORY_REF = "authorization-request-repository-ref";
	private static final String ATT_AUTHORIZATION_REQUEST_RESOLVER_REF = "authorization-request-resolver-ref";
	private static final String ATT_ACCESS_TOKEN_RESPONSE_CLIENT_REF = "access-token-response-client-ref";
	private final BeanReference requestCache;
	private final BeanReference authenticationManager;
	private BeanDefinition defaultAuthorizedClientRepository;
	private BeanDefinition authorizationRequestRedirectFilter;
	private BeanDefinition authorizationCodeGrantFilter;
	private BeanDefinition authorizationCodeAuthenticationProvider;

	OAuth2ClientBeanDefinitionParser(BeanReference requestCache, BeanReference authenticationManager) {
		this.requestCache = requestCache;
		this.authenticationManager = authenticationManager;
	}

	@Override
	public BeanDefinition parse(Element element, ParserContext parserContext) {
		Element authorizationCodeGrantElt = DomUtils.getChildElementByTagName(element, ELT_AUTHORIZATION_CODE_GRANT);

		BeanMetadataElement clientRegistrationRepository = getClientRegistrationRepository(element);
		BeanMetadataElement authorizedClientRepository = getAuthorizedClientRepository(element);
		if (authorizedClientRepository == null) {
			BeanMetadataElement authorizedClientService = getAuthorizedClientService(element);
			if (authorizedClientService == null) {
				this.defaultAuthorizedClientRepository = createDefaultAuthorizedClientRepository(clientRegistrationRepository);
				authorizedClientRepository = this.defaultAuthorizedClientRepository;
			} else {
				authorizedClientRepository = createAuthorizedClientRepository(authorizedClientService);
			}
		}
		BeanMetadataElement authorizationRequestRepository = getAuthorizationRequestRepository(
				authorizationCodeGrantElt);

		BeanDefinitionBuilder authorizationRequestRedirectFilterBuilder = BeanDefinitionBuilder
				.rootBeanDefinition(OAuth2AuthorizationRequestRedirectFilter.class);
		String authorizationRequestResolverRef = authorizationCodeGrantElt != null ?
				authorizationCodeGrantElt.getAttribute(ATT_AUTHORIZATION_REQUEST_RESOLVER_REF) : null;
		if (!StringUtils.isEmpty(authorizationRequestResolverRef)) {
			authorizationRequestRedirectFilterBuilder.addConstructorArgReference(authorizationRequestResolverRef);
		} else {
			authorizationRequestRedirectFilterBuilder.addConstructorArgValue(clientRegistrationRepository);
		}
		this.authorizationRequestRedirectFilter = authorizationRequestRedirectFilterBuilder
				.addPropertyValue("authorizationRequestRepository", authorizationRequestRepository)
				.addPropertyValue("requestCache", this.requestCache)
				.getBeanDefinition();

		this.authorizationCodeGrantFilter = BeanDefinitionBuilder
				.rootBeanDefinition(OAuth2AuthorizationCodeGrantFilter.class)
				.addConstructorArgValue(clientRegistrationRepository)
				.addConstructorArgValue(authorizedClientRepository)
				.addConstructorArgValue(this.authenticationManager)
				.addPropertyValue("authorizationRequestRepository", authorizationRequestRepository)
				.getBeanDefinition();

		BeanMetadataElement accessTokenResponseClient = getAccessTokenResponseClient(authorizationCodeGrantElt);

		this.authorizationCodeAuthenticationProvider = BeanDefinitionBuilder
				.rootBeanDefinition(OAuth2AuthorizationCodeAuthenticationProvider.class)
				.addConstructorArgValue(accessTokenResponseClient)
				.getBeanDefinition();

		return null;
	}

	private BeanMetadataElement getAuthorizationRequestRepository(Element element) {
		BeanMetadataElement authorizationRequestRepository;
		String authorizationRequestRepositoryRef = element != null ?
				element.getAttribute(ATT_AUTHORIZATION_REQUEST_REPOSITORY_REF) : null;
		if (!StringUtils.isEmpty(authorizationRequestRepositoryRef)) {
			authorizationRequestRepository = new RuntimeBeanReference(authorizationRequestRepositoryRef);
		} else {
			authorizationRequestRepository = BeanDefinitionBuilder.rootBeanDefinition(
					"org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository")
					.getBeanDefinition();
		}
		return authorizationRequestRepository;
	}

	private BeanMetadataElement getAccessTokenResponseClient(Element element) {
		BeanMetadataElement accessTokenResponseClient;
		String accessTokenResponseClientRef = element != null ?
				element.getAttribute(ATT_ACCESS_TOKEN_RESPONSE_CLIENT_REF) : null;
		if (!StringUtils.isEmpty(accessTokenResponseClientRef)) {
			accessTokenResponseClient = new RuntimeBeanReference(accessTokenResponseClientRef);
		} else {
			accessTokenResponseClient = BeanDefinitionBuilder.rootBeanDefinition(
					"org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient")
					.getBeanDefinition();
		}
		return accessTokenResponseClient;
	}

	BeanDefinition getDefaultAuthorizedClientRepository() {
		return this.defaultAuthorizedClientRepository;
	}

	BeanDefinition getAuthorizationRequestRedirectFilter() {
		return this.authorizationRequestRedirectFilter;
	}

	BeanDefinition getAuthorizationCodeGrantFilter() {
		return this.authorizationCodeGrantFilter;
	}

	BeanDefinition getAuthorizationCodeAuthenticationProvider() {
		return this.authorizationCodeAuthenticationProvider;
	}
}
