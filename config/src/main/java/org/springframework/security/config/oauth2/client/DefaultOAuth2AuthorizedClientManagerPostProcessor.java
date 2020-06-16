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

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.BeanFactoryAware;
import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.BeanDefinitionRegistryPostProcessor;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.core.Ordered;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.endpoint.DefaultClientCredentialsTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.DefaultPasswordTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.DefaultRefreshTokenTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.web.client.RestOperations;

/**
 * A {@link BeanDefinitionRegistryPostProcessor} that registers a {@link DefaultOAuth2AuthorizedClientManager}
 * {@link BeanDefinition} with the name {@link OAuth2ClientBeanNames#DEFAULT_OAUTH2_AUTHORIZED_CLIENT_MANAGER}.
 *
 * @author Joe Grandja
 * @since 5.4
 */
public final class DefaultOAuth2AuthorizedClientManagerPostProcessor implements BeanDefinitionRegistryPostProcessor, BeanFactoryAware, Ordered {
	private BeanFactory beanFactory;

	@Override
	public void postProcessBeanDefinitionRegistry(BeanDefinitionRegistry registry) throws BeansException {
		if (registry.containsBeanDefinition(OAuth2ClientBeanNames.DEFAULT_OAUTH2_AUTHORIZED_CLIENT_MANAGER)) {
			// Return allowing for bean override
			return;
		}

		boolean clientRegistrationRepositoryAvailable =
				BeanFactoryUtils.beanNamesForTypeIncludingAncestors((ListableBeanFactory) this.beanFactory,
						ClientRegistrationRepository.class, false, false).length == 1;
		boolean authorizedClientRepositoryAvailable =
				BeanFactoryUtils.beanNamesForTypeIncludingAncestors((ListableBeanFactory) this.beanFactory,
						OAuth2AuthorizedClientRepository.class, false, false).length == 1;

		if (clientRegistrationRepositoryAvailable && authorizedClientRepositoryAvailable) {
			AbstractBeanDefinition beanDefinition =
					BeanDefinitionBuilder.genericBeanDefinition(DefaultOAuth2AuthorizedClientManagerFactory.class)
							.getBeanDefinition();
			registry.registerBeanDefinition(OAuth2ClientBeanNames.DEFAULT_OAUTH2_AUTHORIZED_CLIENT_MANAGER, beanDefinition);
		}
	}

	@Override
	public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {
	}

	@Override
	public void setBeanFactory(BeanFactory beanFactory) throws BeansException {
		this.beanFactory = beanFactory;
	}

	@Override
	public int getOrder() {
		return Ordered.LOWEST_PRECEDENCE;
	}

	private static class DefaultOAuth2AuthorizedClientManagerFactory implements FactoryBean<OAuth2AuthorizedClientManager>, ApplicationContextAware {
		private ApplicationContext applicationContext;
		private OAuth2AuthorizedClientManager authorizedClientManager;

		@Override
		public OAuth2AuthorizedClientManager getObject() throws Exception {
			if (this.authorizedClientManager == null) {
				this.authorizedClientManager = createDefaultAuthorizedClientManager();
			}
			return this.authorizedClientManager;
		}

		@Override
		public Class<?> getObjectType() {
			return OAuth2AuthorizedClientManager.class;
		}

		@Override
		public boolean isSingleton() {
			return true;
		}

		@Override
		public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
			this.applicationContext = applicationContext;
		}

		private OAuth2AuthorizedClientManager createDefaultAuthorizedClientManager() {
			ClientRegistrationRepository clientRegistrationRepository =
					this.applicationContext.getBean(ClientRegistrationRepository.class);
			OAuth2AuthorizedClientRepository authorizedClientRepository =
					this.applicationContext.getBean(OAuth2AuthorizedClientRepository.class);
			RestOperations restOperations = this.applicationContext.getBean(
					OAuth2ClientBeanNames.REST_OPERATIONS, RestOperations.class);

			DefaultRefreshTokenTokenResponseClient refreshTokenTokenResponseClient =
					new DefaultRefreshTokenTokenResponseClient();
			refreshTokenTokenResponseClient.setRestOperations(restOperations);

			DefaultClientCredentialsTokenResponseClient clientCredentialsTokenResponseClient =
					new DefaultClientCredentialsTokenResponseClient();
			clientCredentialsTokenResponseClient.setRestOperations(restOperations);

			DefaultPasswordTokenResponseClient passwordTokenResponseClient =
					new DefaultPasswordTokenResponseClient();
			passwordTokenResponseClient.setRestOperations(restOperations);

			OAuth2AuthorizedClientProvider authorizedClientProvider =
					OAuth2AuthorizedClientProviderBuilder.builder()
							.authorizationCode()
							.refreshToken(configurer -> configurer.accessTokenResponseClient(refreshTokenTokenResponseClient))
							.clientCredentials(configurer -> configurer.accessTokenResponseClient(clientCredentialsTokenResponseClient))
							.password(configurer -> configurer.accessTokenResponseClient(passwordTokenResponseClient))
							.build();
			DefaultOAuth2AuthorizedClientManager authorizedClientManager = new DefaultOAuth2AuthorizedClientManager(
					clientRegistrationRepository, authorizedClientRepository);
			authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);

			return authorizedClientManager;
		}
	}
}
