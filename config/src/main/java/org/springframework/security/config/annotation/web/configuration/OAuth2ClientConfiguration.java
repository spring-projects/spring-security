/*
 * Copyright 2002-2023 the original author or authors.
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

import java.util.List;

import org.springframework.beans.BeanMetadataElement;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.BeanFactoryAware;
import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.BeanDefinitionRegistryPostProcessor;
import org.springframework.beans.factory.support.ManagedList;
import org.springframework.context.annotation.AnnotationBeanNameGenerator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.ImportSelector;
import org.springframework.core.ResolvableType;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.oauth2.client.AuthorizationCodeOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.ClientCredentialsOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.DelegatingOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.PasswordOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.RefreshTokenOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2ClientCredentialsGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2PasswordGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.method.annotation.OAuth2AuthorizedClientArgumentResolver;
import org.springframework.util.ClassUtils;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

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
@Import({ OAuth2ClientConfiguration.OAuth2ClientWebMvcImportSelector.class,
		OAuth2ClientConfiguration.OAuth2AuthorizedClientManagerConfiguration.class })
final class OAuth2ClientConfiguration {

	private static final boolean webMvcPresent;

	static {
		ClassLoader classLoader = OAuth2ClientConfiguration.class.getClassLoader();
		webMvcPresent = ClassUtils.isPresent("org.springframework.web.servlet.DispatcherServlet", classLoader);
	}

	static class OAuth2ClientWebMvcImportSelector implements ImportSelector {

		@Override
		public String[] selectImports(AnnotationMetadata importingClassMetadata) {
			if (!webMvcPresent) {
				return new String[0];
			}
			return new String[] {
					OAuth2ClientConfiguration.class.getName() + ".OAuth2ClientWebMvcSecurityConfiguration" };
		}

	}

	/**
	 * @author Joe Grandja
	 * @since 6.2.0
	 */
	@Configuration(proxyBeanMethods = false)
	static class OAuth2AuthorizedClientManagerConfiguration {

		@Bean
		OAuth2AuthorizedClientManagerRegistrar authorizedClientManagerRegistrar() {
			return new OAuth2AuthorizedClientManagerRegistrar();
		}

	}

	@Configuration(proxyBeanMethods = false)
	static class OAuth2ClientWebMvcSecurityConfiguration implements WebMvcConfigurer {

		private ClientRegistrationRepository clientRegistrationRepository;

		private OAuth2AuthorizedClientRepository authorizedClientRepository;

		private OAuth2AccessTokenResponseClient<OAuth2ClientCredentialsGrantRequest> accessTokenResponseClient;

		private OAuth2AuthorizedClientManager authorizedClientManager;

		private SecurityContextHolderStrategy securityContextHolderStrategy;

		@Override
		public void addArgumentResolvers(List<HandlerMethodArgumentResolver> argumentResolvers) {
			OAuth2AuthorizedClientManager authorizedClientManager = getAuthorizedClientManager();
			if (authorizedClientManager != null) {
				OAuth2AuthorizedClientArgumentResolver resolver = new OAuth2AuthorizedClientArgumentResolver(
						authorizedClientManager);
				if (this.securityContextHolderStrategy != null) {
					resolver.setSecurityContextHolderStrategy(this.securityContextHolderStrategy);
				}
				argumentResolvers.add(resolver);
			}
		}

		@Autowired(required = false)
		void setClientRegistrationRepository(List<ClientRegistrationRepository> clientRegistrationRepositories) {
			if (clientRegistrationRepositories.size() == 1) {
				this.clientRegistrationRepository = clientRegistrationRepositories.get(0);
			}
		}

		@Autowired(required = false)
		void setAuthorizedClientRepository(List<OAuth2AuthorizedClientRepository> authorizedClientRepositories) {
			if (authorizedClientRepositories.size() == 1) {
				this.authorizedClientRepository = authorizedClientRepositories.get(0);
			}
		}

		@Autowired(required = false)
		void setAccessTokenResponseClient(
				OAuth2AccessTokenResponseClient<OAuth2ClientCredentialsGrantRequest> accessTokenResponseClient) {
			this.accessTokenResponseClient = accessTokenResponseClient;
		}

		@Autowired(required = false)
		void setAuthorizedClientManager(List<OAuth2AuthorizedClientManager> authorizedClientManagers) {
			if (authorizedClientManagers.size() == 1) {
				this.authorizedClientManager = authorizedClientManagers.get(0);
			}
		}

		@Autowired(required = false)
		void setSecurityContextHolderStrategy(SecurityContextHolderStrategy strategy) {
			this.securityContextHolderStrategy = strategy;
		}

		private OAuth2AuthorizedClientManager getAuthorizedClientManager() {
			if (this.authorizedClientManager != null) {
				return this.authorizedClientManager;
			}
			OAuth2AuthorizedClientManager authorizedClientManager = null;
			if (this.clientRegistrationRepository != null && this.authorizedClientRepository != null) {
				if (this.accessTokenResponseClient != null) {
					// @formatter:off
					OAuth2AuthorizedClientProvider authorizedClientProvider = OAuth2AuthorizedClientProviderBuilder
						.builder()
						.authorizationCode()
						.refreshToken()
						.clientCredentials((configurer) -> configurer.accessTokenResponseClient(this.accessTokenResponseClient))
						.password()
						.build();
					// @formatter:on
					DefaultOAuth2AuthorizedClientManager defaultAuthorizedClientManager = new DefaultOAuth2AuthorizedClientManager(
							this.clientRegistrationRepository, this.authorizedClientRepository);
					defaultAuthorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);
					authorizedClientManager = defaultAuthorizedClientManager;
				}
				else {
					authorizedClientManager = new DefaultOAuth2AuthorizedClientManager(
							this.clientRegistrationRepository, this.authorizedClientRepository);
				}
			}
			return authorizedClientManager;
		}

	}

	/**
	 * A registrar for registering the default {@link OAuth2AuthorizedClientManager} bean
	 * definition, if not already present.
	 *
	 * @author Joe Grandja
	 * @since 6.2.0
	 */
	static class OAuth2AuthorizedClientManagerRegistrar
			implements BeanDefinitionRegistryPostProcessor, BeanFactoryAware {

		private final AnnotationBeanNameGenerator beanNameGenerator = new AnnotationBeanNameGenerator();

		private BeanFactory beanFactory;

		@Override
		public void postProcessBeanDefinitionRegistry(BeanDefinitionRegistry registry) throws BeansException {
			String[] authorizedClientManagerBeanNames = BeanFactoryUtils.beanNamesForTypeIncludingAncestors(
					(ListableBeanFactory) this.beanFactory, OAuth2AuthorizedClientManager.class, true, true);
			if (authorizedClientManagerBeanNames.length != 0) {
				return;
			}

			String[] clientRegistrationRepositoryBeanNames = BeanFactoryUtils.beanNamesForTypeIncludingAncestors(
					(ListableBeanFactory) this.beanFactory, ClientRegistrationRepository.class, true, true);
			String[] authorizedClientRepositoryBeanNames = BeanFactoryUtils.beanNamesForTypeIncludingAncestors(
					(ListableBeanFactory) this.beanFactory, OAuth2AuthorizedClientRepository.class, true, true);
			if (clientRegistrationRepositoryBeanNames.length != 1 || authorizedClientRepositoryBeanNames.length != 1) {
				return;
			}

			BeanDefinition beanDefinition = BeanDefinitionBuilder
					.genericBeanDefinition(DefaultOAuth2AuthorizedClientManager.class)
					.addConstructorArgReference(clientRegistrationRepositoryBeanNames[0])
					.addConstructorArgReference(authorizedClientRepositoryBeanNames[0])
					.addPropertyValue("authorizedClientProvider", getAuthorizedClientProvider()).getBeanDefinition();

			registry.registerBeanDefinition(this.beanNameGenerator.generateBeanName(beanDefinition, registry),
					beanDefinition);
		}

		@Override
		public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {
		}

		private BeanDefinition getAuthorizedClientProvider() {
			ManagedList<Object> authorizedClientProviders = new ManagedList<>();
			authorizedClientProviders.add(getAuthorizationCodeAuthorizedClientProvider());
			authorizedClientProviders.add(getRefreshTokenAuthorizedClientProvider());
			authorizedClientProviders.add(getClientCredentialsAuthorizedClientProvider());
			authorizedClientProviders.add(getPasswordAuthorizedClientProvider());
			return BeanDefinitionBuilder.genericBeanDefinition(DelegatingOAuth2AuthorizedClientProvider.class)
					.addConstructorArgValue(authorizedClientProviders).getBeanDefinition();
		}

		private BeanMetadataElement getAuthorizationCodeAuthorizedClientProvider() {
			String[] beanNames = BeanFactoryUtils.beanNamesForTypeIncludingAncestors(
					(ListableBeanFactory) this.beanFactory, AuthorizationCodeOAuth2AuthorizedClientProvider.class, true,
					true);
			if (beanNames.length == 1) {
				return new RuntimeBeanReference(beanNames[0]);
			}

			return BeanDefinitionBuilder.genericBeanDefinition(AuthorizationCodeOAuth2AuthorizedClientProvider.class)
					.getBeanDefinition();
		}

		private BeanMetadataElement getRefreshTokenAuthorizedClientProvider() {
			String[] beanNames = BeanFactoryUtils.beanNamesForTypeIncludingAncestors(
					(ListableBeanFactory) this.beanFactory, RefreshTokenOAuth2AuthorizedClientProvider.class, true,
					true);
			if (beanNames.length == 1) {
				return new RuntimeBeanReference(beanNames[0]);
			}

			BeanDefinitionBuilder beanDefinitionBuilder = BeanDefinitionBuilder
					.genericBeanDefinition(RefreshTokenOAuth2AuthorizedClientProvider.class);
			ResolvableType resolvableType = ResolvableType.forClassWithGenerics(OAuth2AccessTokenResponseClient.class,
					OAuth2RefreshTokenGrantRequest.class);
			beanNames = BeanFactoryUtils.beanNamesForTypeIncludingAncestors((ListableBeanFactory) this.beanFactory,
					resolvableType, true, true);
			if (beanNames.length == 1) {
				beanDefinitionBuilder.addPropertyReference("accessTokenResponseClient", beanNames[0]);
			}
			return beanDefinitionBuilder.getBeanDefinition();
		}

		private BeanMetadataElement getClientCredentialsAuthorizedClientProvider() {
			String[] beanNames = BeanFactoryUtils.beanNamesForTypeIncludingAncestors(
					(ListableBeanFactory) this.beanFactory, ClientCredentialsOAuth2AuthorizedClientProvider.class, true,
					true);
			if (beanNames.length == 1) {
				return new RuntimeBeanReference(beanNames[0]);
			}

			BeanDefinitionBuilder beanDefinitionBuilder = BeanDefinitionBuilder
					.genericBeanDefinition(ClientCredentialsOAuth2AuthorizedClientProvider.class);
			ResolvableType resolvableType = ResolvableType.forClassWithGenerics(OAuth2AccessTokenResponseClient.class,
					OAuth2ClientCredentialsGrantRequest.class);
			beanNames = BeanFactoryUtils.beanNamesForTypeIncludingAncestors((ListableBeanFactory) this.beanFactory,
					resolvableType, true, true);
			if (beanNames.length == 1) {
				beanDefinitionBuilder.addPropertyReference("accessTokenResponseClient", beanNames[0]);
			}
			return beanDefinitionBuilder.getBeanDefinition();
		}

		private BeanMetadataElement getPasswordAuthorizedClientProvider() {
			String[] beanNames = BeanFactoryUtils.beanNamesForTypeIncludingAncestors(
					(ListableBeanFactory) this.beanFactory, PasswordOAuth2AuthorizedClientProvider.class, true, true);
			if (beanNames.length == 1) {
				return new RuntimeBeanReference(beanNames[0]);
			}

			BeanDefinitionBuilder beanDefinitionBuilder = BeanDefinitionBuilder
					.genericBeanDefinition(PasswordOAuth2AuthorizedClientProvider.class);
			ResolvableType resolvableType = ResolvableType.forClassWithGenerics(OAuth2AccessTokenResponseClient.class,
					OAuth2PasswordGrantRequest.class);
			beanNames = BeanFactoryUtils.beanNamesForTypeIncludingAncestors((ListableBeanFactory) this.beanFactory,
					resolvableType, true, true);
			if (beanNames.length == 1) {
				beanDefinitionBuilder.addPropertyReference("accessTokenResponseClient", beanNames[0]);
			}
			return beanDefinitionBuilder.getBeanDefinition();
		}

		@Override
		public void setBeanFactory(BeanFactory beanFactory) throws BeansException {
			this.beanFactory = beanFactory;
		}

	}

}
