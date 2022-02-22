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

package org.springframework.security.config.annotation.web.reactive;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportSelector;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.reactive.result.method.annotation.OAuth2AuthorizedClientArgumentResolver;
import org.springframework.security.oauth2.client.web.server.AuthenticatedPrincipalServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.util.ClassUtils;
import org.springframework.web.reactive.config.WebFluxConfigurer;
import org.springframework.web.reactive.result.method.annotation.ArgumentResolverConfigurer;

/**
 * {@link Configuration} for OAuth 2.0 Client support.
 *
 * <p>
 * This {@code Configuration} is imported by {@link EnableWebFluxSecurity}
 *
 * @author Rob Winch
 * @author Alavudin Kuttikkattil
 * @since 5.1
 */
final class ReactiveOAuth2ClientImportSelector implements ImportSelector {

	@Override
	public String[] selectImports(AnnotationMetadata importingClassMetadata) {
		if (!ClassUtils.isPresent("org.springframework.security.oauth2.client.registration.ClientRegistration",
				getClass().getClassLoader())) {
			return new String[0];
		}
		return new String[] { "org.springframework.security.config.annotation.web.reactive."
				+ "ReactiveOAuth2ClientImportSelector$OAuth2ClientWebFluxSecurityConfiguration" };
	}

	@Configuration(proxyBeanMethods = false)
	static class OAuth2ClientWebFluxSecurityConfiguration implements WebFluxConfigurer {

		private ReactiveClientRegistrationRepository clientRegistrationRepository;

		private ServerOAuth2AuthorizedClientRepository authorizedClientRepository;

		private ReactiveOAuth2AuthorizedClientService authorizedClientService;

		private ReactiveOAuth2AuthorizedClientManager authorizedClientManager;

		@Override
		public void configureArgumentResolvers(ArgumentResolverConfigurer configurer) {
			ReactiveOAuth2AuthorizedClientManager authorizedClientManager = getAuthorizedClientManager();
			if (authorizedClientManager != null) {
				configurer.addCustomResolver(new OAuth2AuthorizedClientArgumentResolver(authorizedClientManager));
			}
		}

		@Autowired(required = false)
		void setClientRegistrationRepository(ReactiveClientRegistrationRepository clientRegistrationRepository) {
			this.clientRegistrationRepository = clientRegistrationRepository;
		}

		@Autowired(required = false)
		void setAuthorizedClientRepository(ServerOAuth2AuthorizedClientRepository authorizedClientRepository) {
			this.authorizedClientRepository = authorizedClientRepository;
		}

		@Autowired(required = false)
		void setAuthorizedClientService(List<ReactiveOAuth2AuthorizedClientService> authorizedClientService) {
			if (authorizedClientService.size() == 1) {
				this.authorizedClientService = authorizedClientService.get(0);
			}
		}

		@Autowired(required = false)
		void setAuthorizedClientManager(List<ReactiveOAuth2AuthorizedClientManager> authorizedClientManager) {
			if (authorizedClientManager.size() == 1) {
				this.authorizedClientManager = authorizedClientManager.get(0);
			}
		}

		private ServerOAuth2AuthorizedClientRepository getAuthorizedClientRepository() {
			if (this.authorizedClientRepository != null) {
				return this.authorizedClientRepository;
			}
			if (this.authorizedClientService != null) {
				return new AuthenticatedPrincipalServerOAuth2AuthorizedClientRepository(this.authorizedClientService);
			}
			return null;
		}

		private ReactiveOAuth2AuthorizedClientManager getAuthorizedClientManager() {
			if (this.authorizedClientManager != null) {
				return this.authorizedClientManager;
			}
			ReactiveOAuth2AuthorizedClientManager authorizedClientManager = null;
			if (this.authorizedClientRepository != null && this.clientRegistrationRepository != null) {
				ReactiveOAuth2AuthorizedClientProvider authorizedClientProvider = ReactiveOAuth2AuthorizedClientProviderBuilder
						.builder().authorizationCode().refreshToken().clientCredentials().password().build();
				DefaultReactiveOAuth2AuthorizedClientManager defaultReactiveOAuth2AuthorizedClientManager = new DefaultReactiveOAuth2AuthorizedClientManager(
						this.clientRegistrationRepository, getAuthorizedClientRepository());
				defaultReactiveOAuth2AuthorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);
				authorizedClientManager = defaultReactiveOAuth2AuthorizedClientManager;
			}

			return authorizedClientManager;
		}

	}

}
