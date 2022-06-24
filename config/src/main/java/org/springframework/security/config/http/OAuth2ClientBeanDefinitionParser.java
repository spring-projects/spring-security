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
import org.springframework.beans.factory.config.BeanReference;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthorizationCodeAuthenticationProvider;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationCodeGrantFilter;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;

/**
 * @author Joe Grandja
 * @since 5.3
 */
final class OAuth2ClientBeanDefinitionParser implements BeanDefinitionParser {

	private static final String ELT_AUTHORIZATION_CODE_GRANT = "authorization-code-grant";

	private static final String ATT_AUTHORIZATION_REQUEST_REPOSITORY_REF = "authorization-request-repository-ref";

	private static final String ATT_AUTHORIZATION_REQUEST_RESOLVER_REF = "authorization-request-resolver-ref";

	private static final String ATT_AUTHORIZATION_REDIRECT_STRATEGY_REF = "authorization-redirect-strategy-ref";

	private static final String ATT_ACCESS_TOKEN_RESPONSE_CLIENT_REF = "access-token-response-client-ref";

	private final BeanReference requestCache;

	private final BeanReference authenticationManager;

	private final BeanReference authenticationFilterSecurityContextRepositoryRef;

	private final BeanMetadataElement authenticationFilterSecurityContextHolderStrategy;

	private BeanDefinition defaultAuthorizedClientRepository;

	private BeanDefinition authorizationRequestRedirectFilter;

	private BeanDefinition authorizationCodeGrantFilter;

	private BeanDefinition authorizationCodeAuthenticationProvider;

	OAuth2ClientBeanDefinitionParser(BeanReference requestCache, BeanReference authenticationManager,
			BeanReference authenticationFilterSecurityContextRepositoryRef,
			BeanMetadataElement authenticationFilterSecurityContextHolderStrategy) {
		this.requestCache = requestCache;
		this.authenticationManager = authenticationManager;
		this.authenticationFilterSecurityContextRepositoryRef = authenticationFilterSecurityContextRepositoryRef;
		this.authenticationFilterSecurityContextHolderStrategy = authenticationFilterSecurityContextHolderStrategy;
	}

	@Override
	public BeanDefinition parse(Element element, ParserContext parserContext) {
		Element authorizationCodeGrantElt = DomUtils.getChildElementByTagName(element, ELT_AUTHORIZATION_CODE_GRANT);
		BeanMetadataElement clientRegistrationRepository = OAuth2ClientBeanDefinitionParserUtils
				.getClientRegistrationRepository(element);
		BeanMetadataElement authorizedClientRepository = OAuth2ClientBeanDefinitionParserUtils
				.getAuthorizedClientRepository(element);
		if (authorizedClientRepository == null) {
			BeanMetadataElement authorizedClientService = OAuth2ClientBeanDefinitionParserUtils
					.getAuthorizedClientService(element);
			this.defaultAuthorizedClientRepository = OAuth2ClientBeanDefinitionParserUtils
					.createDefaultAuthorizedClientRepository(clientRegistrationRepository, authorizedClientService);
			authorizedClientRepository = new RuntimeBeanReference(OAuth2AuthorizedClientRepository.class);
		}
		BeanMetadataElement authorizationRequestRepository = getAuthorizationRequestRepository(
				authorizationCodeGrantElt);
		BeanMetadataElement authorizationRedirectStrategy = getAuthorizationRedirectStrategy(authorizationCodeGrantElt);
		BeanDefinitionBuilder authorizationRequestRedirectFilterBuilder = BeanDefinitionBuilder
				.rootBeanDefinition(OAuth2AuthorizationRequestRedirectFilter.class);
		String authorizationRequestResolverRef = (authorizationCodeGrantElt != null)
				? authorizationCodeGrantElt.getAttribute(ATT_AUTHORIZATION_REQUEST_RESOLVER_REF) : null;
		if (!StringUtils.isEmpty(authorizationRequestResolverRef)) {
			authorizationRequestRedirectFilterBuilder.addConstructorArgReference(authorizationRequestResolverRef);
		}
		else {
			authorizationRequestRedirectFilterBuilder.addConstructorArgValue(clientRegistrationRepository);
		}
		this.authorizationRequestRedirectFilter = authorizationRequestRedirectFilterBuilder
				.addPropertyValue("authorizationRequestRepository", authorizationRequestRepository)
				.addPropertyValue("authorizationRedirectStrategy", authorizationRedirectStrategy)
				.addPropertyValue("requestCache", this.requestCache).getBeanDefinition();
		BeanDefinitionBuilder authorizationCodeGrantFilterBldr = BeanDefinitionBuilder
				.rootBeanDefinition(OAuth2AuthorizationCodeGrantFilter.class)
				.addConstructorArgValue(clientRegistrationRepository).addConstructorArgValue(authorizedClientRepository)
				.addConstructorArgValue(this.authenticationManager)
				.addPropertyValue("authorizationRequestRepository", authorizationRequestRepository);
		this.authorizationCodeGrantFilter = authorizationCodeGrantFilterBldr.getBeanDefinition();

		BeanMetadataElement accessTokenResponseClient = getAccessTokenResponseClient(authorizationCodeGrantElt);
		this.authorizationCodeAuthenticationProvider = BeanDefinitionBuilder
				.rootBeanDefinition(OAuth2AuthorizationCodeAuthenticationProvider.class)
				.addConstructorArgValue(accessTokenResponseClient).getBeanDefinition();

		return null;
	}

	private BeanMetadataElement getAuthorizationRequestRepository(Element element) {
		String authorizationRequestRepositoryRef = (element != null)
				? element.getAttribute(ATT_AUTHORIZATION_REQUEST_REPOSITORY_REF) : null;
		if (!StringUtils.isEmpty(authorizationRequestRepositoryRef)) {
			return new RuntimeBeanReference(authorizationRequestRepositoryRef);
		}
		return BeanDefinitionBuilder.rootBeanDefinition(
				"org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository")
				.getBeanDefinition();
	}

	private BeanMetadataElement getAuthorizationRedirectStrategy(Element element) {
		String authorizationRedirectStrategyRef = (element != null)
				? element.getAttribute(ATT_AUTHORIZATION_REDIRECT_STRATEGY_REF) : null;
		if (StringUtils.hasText(authorizationRedirectStrategyRef)) {
			return new RuntimeBeanReference(authorizationRedirectStrategyRef);
		}
		return BeanDefinitionBuilder.rootBeanDefinition("org.springframework.security.web.DefaultRedirectStrategy")
				.getBeanDefinition();
	}

	private BeanMetadataElement getAccessTokenResponseClient(Element element) {
		String accessTokenResponseClientRef = (element != null)
				? element.getAttribute(ATT_ACCESS_TOKEN_RESPONSE_CLIENT_REF) : null;
		if (!StringUtils.isEmpty(accessTokenResponseClientRef)) {
			return new RuntimeBeanReference(accessTokenResponseClientRef);
		}
		return BeanDefinitionBuilder.rootBeanDefinition(
				"org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient")
				.getBeanDefinition();
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
