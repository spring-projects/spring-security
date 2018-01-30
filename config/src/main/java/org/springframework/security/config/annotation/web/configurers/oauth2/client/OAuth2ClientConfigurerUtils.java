/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.config.annotation.web.configurers.oauth2.client;

import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;

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
		ClientRegistrationRepository clientRegistrationRepository = builder.getSharedObject(ClientRegistrationRepository.class);
		if (clientRegistrationRepository == null) {
			clientRegistrationRepository = getClientRegistrationRepositoryBean(builder);
			builder.setSharedObject(ClientRegistrationRepository.class, clientRegistrationRepository);
		}
		return clientRegistrationRepository;
	}

	private static <B extends HttpSecurityBuilder<B>> ClientRegistrationRepository getClientRegistrationRepositoryBean(B builder) {
		return builder.getSharedObject(ApplicationContext.class).getBean(ClientRegistrationRepository.class);
	}

	static <B extends HttpSecurityBuilder<B>> OAuth2AuthorizedClientService getAuthorizedClientService(B builder) {
		OAuth2AuthorizedClientService authorizedClientService = builder.getSharedObject(OAuth2AuthorizedClientService.class);
		if (authorizedClientService == null) {
			authorizedClientService = getAuthorizedClientServiceBean(builder);
			if (authorizedClientService == null) {
				authorizedClientService = new InMemoryOAuth2AuthorizedClientService(getClientRegistrationRepository(builder));
			}
			builder.setSharedObject(OAuth2AuthorizedClientService.class, authorizedClientService);
		}
		return authorizedClientService;
	}

	private static <B extends HttpSecurityBuilder<B>> OAuth2AuthorizedClientService getAuthorizedClientServiceBean(B builder) {
		Map<String, OAuth2AuthorizedClientService> authorizedClientServiceMap = BeanFactoryUtils.beansOfTypeIncludingAncestors(
				builder.getSharedObject(ApplicationContext.class), OAuth2AuthorizedClientService.class);
		return (!authorizedClientServiceMap.isEmpty() ? authorizedClientServiceMap.values().iterator().next() : null);
	}
}
