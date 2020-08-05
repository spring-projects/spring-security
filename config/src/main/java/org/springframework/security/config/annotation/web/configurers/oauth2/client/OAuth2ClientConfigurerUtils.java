/*
 * Copyright 2002-2018 the original author or authors.
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
package org.springframework.security.config.annotation.web.configurers.oauth2.client;

import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.NoUniqueBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.AuthenticatedPrincipalOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.util.StringUtils;

import java.util.Map;

/**
 * Utility methods for the OAuth 2.0 Client {@link AbstractHttpConfigurer}'s.
 *
 * @author Joe Grandja
 * @since 5.1
 */
final class OAuth2ClientConfigurerUtils {

	private OAuth2ClientConfigurerUtils() {
	}

	static <B extends HttpSecurityBuilder<B>> ClientRegistrationRepository getClientRegistrationRepository(B builder) {
		ClientRegistrationRepository clientRegistrationRepository = builder
				.getSharedObject(ClientRegistrationRepository.class);
		if (clientRegistrationRepository == null) {
			clientRegistrationRepository = getClientRegistrationRepositoryBean(builder);
			builder.setSharedObject(ClientRegistrationRepository.class, clientRegistrationRepository);
		}
		return clientRegistrationRepository;
	}

	private static <B extends HttpSecurityBuilder<B>> ClientRegistrationRepository getClientRegistrationRepositoryBean(
			B builder) {
		return builder.getSharedObject(ApplicationContext.class).getBean(ClientRegistrationRepository.class);
	}

	static <B extends HttpSecurityBuilder<B>> OAuth2AuthorizedClientRepository getAuthorizedClientRepository(
			B builder) {
		OAuth2AuthorizedClientRepository authorizedClientRepository = builder
				.getSharedObject(OAuth2AuthorizedClientRepository.class);
		if (authorizedClientRepository == null) {
			authorizedClientRepository = getAuthorizedClientRepositoryBean(builder);
			if (authorizedClientRepository == null) {
				authorizedClientRepository = new AuthenticatedPrincipalOAuth2AuthorizedClientRepository(
						getAuthorizedClientService((builder)));
			}
			builder.setSharedObject(OAuth2AuthorizedClientRepository.class, authorizedClientRepository);
		}
		return authorizedClientRepository;
	}

	private static <B extends HttpSecurityBuilder<B>> OAuth2AuthorizedClientRepository getAuthorizedClientRepositoryBean(
			B builder) {
		Map<String, OAuth2AuthorizedClientRepository> authorizedClientRepositoryMap = BeanFactoryUtils
				.beansOfTypeIncludingAncestors(builder.getSharedObject(ApplicationContext.class),
						OAuth2AuthorizedClientRepository.class);
		if (authorizedClientRepositoryMap.size() > 1) {
			throw new NoUniqueBeanDefinitionException(OAuth2AuthorizedClientRepository.class,
					authorizedClientRepositoryMap.size(),
					"Expected single matching bean of type '" + OAuth2AuthorizedClientRepository.class.getName()
							+ "' but found " + authorizedClientRepositoryMap.size() + ": "
							+ StringUtils.collectionToCommaDelimitedString(authorizedClientRepositoryMap.keySet()));
		}
		return (!authorizedClientRepositoryMap.isEmpty() ? authorizedClientRepositoryMap.values().iterator().next()
				: null);
	}

	private static <B extends HttpSecurityBuilder<B>> OAuth2AuthorizedClientService getAuthorizedClientService(
			B builder) {
		OAuth2AuthorizedClientService authorizedClientService = getAuthorizedClientServiceBean(builder);
		if (authorizedClientService == null) {
			authorizedClientService = new InMemoryOAuth2AuthorizedClientService(
					getClientRegistrationRepository(builder));
		}
		return authorizedClientService;
	}

	private static <B extends HttpSecurityBuilder<B>> OAuth2AuthorizedClientService getAuthorizedClientServiceBean(
			B builder) {
		Map<String, OAuth2AuthorizedClientService> authorizedClientServiceMap = BeanFactoryUtils
				.beansOfTypeIncludingAncestors(builder.getSharedObject(ApplicationContext.class),
						OAuth2AuthorizedClientService.class);
		if (authorizedClientServiceMap.size() > 1) {
			throw new NoUniqueBeanDefinitionException(OAuth2AuthorizedClientService.class,
					authorizedClientServiceMap.size(),
					"Expected single matching bean of type '" + OAuth2AuthorizedClientService.class.getName()
							+ "' but found " + authorizedClientServiceMap.size() + ": "
							+ StringUtils.collectionToCommaDelimitedString(authorizedClientServiceMap.keySet()));
		}
		return (!authorizedClientServiceMap.isEmpty() ? authorizedClientServiceMap.values().iterator().next() : null);
	}

}
