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

package org.springframework.security.config.annotation.web.reactive;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportSelector;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.server.AuthenticatedPrincipalServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.reactive.result.method.annotation.OAuth2AuthorizedClientArgumentResolver;
import org.springframework.util.ClassUtils;
import org.springframework.web.reactive.config.WebFluxConfigurer;
import org.springframework.web.reactive.result.method.annotation.ArgumentResolverConfigurer;

import java.util.List;

/**
 * {@link Configuration} for OAuth 2.0 Client support.
 *
 * <p>
 * This {@code Configuration} is imported by {@link EnableWebFluxSecurity}
 *
 * @author Rob Winch
 * @since 5.1
 */
final class ReactiveOAuth2ClientImportSelector implements ImportSelector {

	@Override
	public String[] selectImports(AnnotationMetadata importingClassMetadata) {
		boolean oauth2ClientPresent = ClassUtils.isPresent(
				"org.springframework.security.oauth2.client.registration.ClientRegistration", getClass().getClassLoader());

		return oauth2ClientPresent ?
			new String[] { "org.springframework.security.config.annotation.web.reactive.ReactiveOAuth2ClientImportSelector$OAuth2ClientWebFluxSecurityConfiguration" } :
			new String[] {};
	}

	@Configuration
	static class OAuth2ClientWebFluxSecurityConfiguration implements WebFluxConfigurer {
		private ReactiveClientRegistrationRepository clientRegistrationRepository;

		private ServerOAuth2AuthorizedClientRepository authorizedClientRepository;

		private ReactiveOAuth2AuthorizedClientService authorizedClientService;

		@Override
		public void configureArgumentResolvers(ArgumentResolverConfigurer configurer) {
			if (this.authorizedClientRepository != null && this.clientRegistrationRepository != null) {
				configurer.addCustomResolver(new OAuth2AuthorizedClientArgumentResolver(this.clientRegistrationRepository, getAuthorizedClientRepository()));
			}
		}

		@Autowired(required = false)
		public void setClientRegistrationRepository(
				ReactiveClientRegistrationRepository clientRegistrationRepository) {
			this.clientRegistrationRepository = clientRegistrationRepository;
		}

		@Autowired(required = false)
		public void setAuthorizedClientRepository(ServerOAuth2AuthorizedClientRepository authorizedClientRepository) {
			this.authorizedClientRepository = authorizedClientRepository;
		}

		@Autowired(required = false)
		public void setAuthorizedClientService(List<ReactiveOAuth2AuthorizedClientService> authorizedClientService) {
			if (authorizedClientService.size() == 1) {
				this.authorizedClientService = authorizedClientService.get(0);
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
	}
}
