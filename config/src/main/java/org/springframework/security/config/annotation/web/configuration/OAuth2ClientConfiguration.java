/*
 * Copyright 2002-2019 the original author or authors.
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
package org.springframework.security.config.annotation.web.configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.ImportSelector;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2ClientCredentialsGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.method.annotation.OAuth2AuthorizedClientArgumentResolver;
import org.springframework.util.ClassUtils;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.List;
import java.util.Optional;

/**
 * {@link Configuration} for OAuth 2.0 Client support.
 *
 * <p>
 * This {@code Configuration} is conditionally imported by {@link OAuth2ImportSelector}
 * when the {@code spring-security-oauth2-client} module is present on the classpath.
 *
 * @author Joe Grandja
 * @since 5.1
 * @see OAuth2ImportSelector
 */
@Import(OAuth2ClientConfiguration.OAuth2ClientWebMvcImportSelector.class)
final class OAuth2ClientConfiguration {

	static class OAuth2ClientWebMvcImportSelector implements ImportSelector {

		@Override
		public String[] selectImports(AnnotationMetadata importingClassMetadata) {
			boolean webmvcPresent = ClassUtils.isPresent(
				"org.springframework.web.servlet.DispatcherServlet", getClass().getClassLoader());

			return webmvcPresent ?
				new String[] { "org.springframework.security.config.annotation.web.configuration.OAuth2ClientConfiguration.OAuth2ClientWebMvcSecurityConfiguration" } :
				new String[] {};
		}
	}

	@Configuration(proxyBeanMethods = false)
	static class OAuth2ClientWebMvcSecurityConfiguration implements WebMvcConfigurer {
		private ClientRegistrationRepository clientRegistrationRepository;
		private OAuth2AuthorizedClientRepository authorizedClientRepository;
		private OAuth2AccessTokenResponseClient<OAuth2ClientCredentialsGrantRequest> accessTokenResponseClient;

		@Override
		public void addArgumentResolvers(List<HandlerMethodArgumentResolver> argumentResolvers) {
			if (this.clientRegistrationRepository != null && this.authorizedClientRepository != null) {
				OAuth2AuthorizedClientProviderBuilder authorizedClientProviderBuilder =
						OAuth2AuthorizedClientProviderBuilder.builder()
								.authorizationCode()
								.refreshToken();

				if (this.accessTokenResponseClient != null) {
					authorizedClientProviderBuilder.clientCredentials(configurer ->
									configurer.accessTokenResponseClient(this.accessTokenResponseClient));
				} else {
					authorizedClientProviderBuilder.clientCredentials();
				}
				OAuth2AuthorizedClientProvider authorizedClientProvider = authorizedClientProviderBuilder.build();

				DefaultOAuth2AuthorizedClientManager authorizedClientManager = new DefaultOAuth2AuthorizedClientManager(
						this.clientRegistrationRepository, this.authorizedClientRepository);
				authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);
				argumentResolvers.add(new OAuth2AuthorizedClientArgumentResolver(authorizedClientManager));
			}
		}

		@Autowired(required = false)
		public void setClientRegistrationRepository(List<ClientRegistrationRepository> clientRegistrationRepositories) {
			if (clientRegistrationRepositories.size() == 1) {
				this.clientRegistrationRepository = clientRegistrationRepositories.get(0);
			}
		}

		@Autowired(required = false)
		public void setAuthorizedClientRepository(List<OAuth2AuthorizedClientRepository> authorizedClientRepositories) {
			if (authorizedClientRepositories.size() == 1) {
				this.authorizedClientRepository = authorizedClientRepositories.get(0);
			}
		}

		@Autowired
		public void setAccessTokenResponseClient(
				Optional<OAuth2AccessTokenResponseClient<OAuth2ClientCredentialsGrantRequest>> accessTokenResponseClient) {
			accessTokenResponseClient.ifPresent(client -> this.accessTokenResponseClient = client);
		}
	}
}
