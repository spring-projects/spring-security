/*
 * Copyright 2002-2024 the original author or authors.
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

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.BeanFactoryAware;
import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.BeanInitializationException;
import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.BeanDefinitionRegistryPostProcessor;
import org.springframework.context.annotation.AnnotationBeanNameGenerator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.ResolvableType;
import org.springframework.security.oauth2.client.AuthorizationCodeReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.ClientCredentialsReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.DelegatingReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.JwtBearerReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.PasswordReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.RefreshTokenReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.TokenExchangeReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.endpoint.JwtBearerGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2ClientCredentialsGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2PasswordGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequest;
import org.springframework.security.oauth2.client.endpoint.ReactiveOAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.TokenExchangeGrantRequest;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.reactive.result.method.annotation.OAuth2AuthorizedClientArgumentResolver;
import org.springframework.security.oauth2.client.web.server.AuthenticatedPrincipalServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.web.reactive.config.WebFluxConfigurer;
import org.springframework.web.reactive.result.method.annotation.ArgumentResolverConfigurer;

/**
 * {@link Configuration} for OAuth 2.0 Client support.
 *
 * <p>
 * This {@code Configuration} is conditionally imported by
 * {@link ReactiveOAuth2ClientImportSelector} when the
 * {@code spring-security-oauth2-client} module is present on the classpath.
 *
 * @author Steve Riesenberg
 * @since 6.3
 * @see ReactiveOAuth2ClientImportSelector
 */
@Import({ ReactiveOAuth2ClientConfiguration.ReactiveOAuth2AuthorizedClientManagerConfiguration.class,
		ReactiveOAuth2ClientConfiguration.OAuth2ClientWebFluxSecurityConfiguration.class })
final class ReactiveOAuth2ClientConfiguration {

	@Configuration(proxyBeanMethods = false)
	static class ReactiveOAuth2AuthorizedClientManagerConfiguration {

		@Bean(name = ReactiveOAuth2AuthorizedClientManagerRegistrar.BEAN_NAME)
		ReactiveOAuth2AuthorizedClientManagerRegistrar authorizedClientManagerRegistrar() {
			return new ReactiveOAuth2AuthorizedClientManagerRegistrar();
		}

	}

	@Configuration(proxyBeanMethods = false)
	static class OAuth2ClientWebFluxSecurityConfiguration implements WebFluxConfigurer {

		private final ReactiveOAuth2AuthorizedClientManager authorizedClientManager;

		private final ReactiveOAuth2AuthorizedClientManagerRegistrar authorizedClientManagerRegistrar;

		OAuth2ClientWebFluxSecurityConfiguration(
				ObjectProvider<ReactiveOAuth2AuthorizedClientManager> authorizedClientManager,
				ReactiveOAuth2AuthorizedClientManagerRegistrar authorizedClientManagerRegistrar) {
			this.authorizedClientManager = authorizedClientManager.getIfUnique();
			this.authorizedClientManagerRegistrar = authorizedClientManagerRegistrar;
		}

		@Override
		public void configureArgumentResolvers(ArgumentResolverConfigurer configurer) {
			ReactiveOAuth2AuthorizedClientManager authorizedClientManager = getAuthorizedClientManager();
			if (authorizedClientManager != null) {
				configurer.addCustomResolver(new OAuth2AuthorizedClientArgumentResolver(authorizedClientManager));
			}
		}

		private ReactiveOAuth2AuthorizedClientManager getAuthorizedClientManager() {
			if (this.authorizedClientManager != null) {
				return this.authorizedClientManager;
			}
			return this.authorizedClientManagerRegistrar.getAuthorizedClientManagerIfAvailable();
		}

	}

	/**
	 * A registrar for registering the default
	 * {@link ReactiveOAuth2AuthorizedClientManager} bean definition, if not already
	 * present.
	 */
	static final class ReactiveOAuth2AuthorizedClientManagerRegistrar
			implements BeanDefinitionRegistryPostProcessor, BeanFactoryAware {

		static final String BEAN_NAME = "authorizedClientManagerRegistrar";

		static final String FACTORY_METHOD_NAME = "getAuthorizedClientManager";

		// @formatter:off
		private static final Set<Class<?>> KNOWN_AUTHORIZED_CLIENT_PROVIDERS = Set.of(
				AuthorizationCodeReactiveOAuth2AuthorizedClientProvider.class,
				RefreshTokenReactiveOAuth2AuthorizedClientProvider.class,
				ClientCredentialsReactiveOAuth2AuthorizedClientProvider.class,
				PasswordReactiveOAuth2AuthorizedClientProvider.class,
				JwtBearerReactiveOAuth2AuthorizedClientProvider.class,
				TokenExchangeReactiveOAuth2AuthorizedClientProvider.class
		);
		// @formatter:on

		private final AnnotationBeanNameGenerator beanNameGenerator = new AnnotationBeanNameGenerator();

		private ListableBeanFactory beanFactory;

		@Override
		public void postProcessBeanDefinitionRegistry(BeanDefinitionRegistry registry) throws BeansException {
			if (getBeanNamesForType(ReactiveOAuth2AuthorizedClientManager.class).length != 0
					|| getBeanNamesForType(ReactiveClientRegistrationRepository.class).length != 1
					|| getBeanNamesForType(ServerOAuth2AuthorizedClientRepository.class).length != 1
							&& getBeanNamesForType(ReactiveOAuth2AuthorizedClientService.class).length != 1) {
				return;
			}

			BeanDefinition beanDefinition = BeanDefinitionBuilder
				.rootBeanDefinition(ReactiveOAuth2AuthorizedClientManager.class)
				.setFactoryMethodOnBean(FACTORY_METHOD_NAME, BEAN_NAME)
				.getBeanDefinition();

			registry.registerBeanDefinition(this.beanNameGenerator.generateBeanName(beanDefinition, registry),
					beanDefinition);
		}

		@Override
		public void setBeanFactory(BeanFactory beanFactory) throws BeansException {
			this.beanFactory = (ListableBeanFactory) beanFactory;
		}

		ReactiveOAuth2AuthorizedClientManager getAuthorizedClientManagerIfAvailable() {
			if (getBeanNamesForType(ReactiveClientRegistrationRepository.class).length != 1
					|| getBeanNamesForType(ServerOAuth2AuthorizedClientRepository.class).length != 1
							&& getBeanNamesForType(ReactiveOAuth2AuthorizedClientService.class).length != 1) {
				return null;
			}
			return getAuthorizedClientManager();
		}

		ReactiveOAuth2AuthorizedClientManager getAuthorizedClientManager() {
			ReactiveClientRegistrationRepository clientRegistrationRepository = BeanFactoryUtils
				.beanOfTypeIncludingAncestors(this.beanFactory, ReactiveClientRegistrationRepository.class, true, true);

			ServerOAuth2AuthorizedClientRepository authorizedClientRepository;
			try {
				authorizedClientRepository = BeanFactoryUtils.beanOfTypeIncludingAncestors(this.beanFactory,
						ServerOAuth2AuthorizedClientRepository.class, true, true);
			}
			catch (NoSuchBeanDefinitionException ex) {
				ReactiveOAuth2AuthorizedClientService authorizedClientService = BeanFactoryUtils
					.beanOfTypeIncludingAncestors(this.beanFactory, ReactiveOAuth2AuthorizedClientService.class, true,
							true);
				authorizedClientRepository = new AuthenticatedPrincipalServerOAuth2AuthorizedClientRepository(
						authorizedClientService);
			}

			Collection<ReactiveOAuth2AuthorizedClientProvider> authorizedClientProviderBeans = BeanFactoryUtils
				.beansOfTypeIncludingAncestors(this.beanFactory, ReactiveOAuth2AuthorizedClientProvider.class, true,
						true)
				.values();

			ReactiveOAuth2AuthorizedClientProvider authorizedClientProvider;
			if (hasDelegatingAuthorizedClientProvider(authorizedClientProviderBeans)) {
				authorizedClientProvider = authorizedClientProviderBeans.iterator().next();
			}
			else {
				List<ReactiveOAuth2AuthorizedClientProvider> authorizedClientProviders = new ArrayList<>();
				authorizedClientProviders
					.add(getAuthorizationCodeAuthorizedClientProvider(authorizedClientProviderBeans));
				authorizedClientProviders.add(getRefreshTokenAuthorizedClientProvider(authorizedClientProviderBeans));
				authorizedClientProviders
					.add(getClientCredentialsAuthorizedClientProvider(authorizedClientProviderBeans));
				authorizedClientProviders.add(getPasswordAuthorizedClientProvider(authorizedClientProviderBeans));

				ReactiveOAuth2AuthorizedClientProvider jwtBearerAuthorizedClientProvider = getJwtBearerAuthorizedClientProvider(
						authorizedClientProviderBeans);
				if (jwtBearerAuthorizedClientProvider != null) {
					authorizedClientProviders.add(jwtBearerAuthorizedClientProvider);
				}

				ReactiveOAuth2AuthorizedClientProvider tokenExchangeAuthorizedClientProvider = getTokenExchangeAuthorizedClientProvider(
						authorizedClientProviderBeans);
				if (tokenExchangeAuthorizedClientProvider != null) {
					authorizedClientProviders.add(tokenExchangeAuthorizedClientProvider);
				}

				authorizedClientProviders.addAll(getAdditionalAuthorizedClientProviders(authorizedClientProviderBeans));
				authorizedClientProvider = new DelegatingReactiveOAuth2AuthorizedClientProvider(
						authorizedClientProviders);
			}

			DefaultReactiveOAuth2AuthorizedClientManager authorizedClientManager = new DefaultReactiveOAuth2AuthorizedClientManager(
					clientRegistrationRepository, authorizedClientRepository);
			authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);

			Consumer<DefaultReactiveOAuth2AuthorizedClientManager> authorizedClientManagerConsumer = getBeanOfType(
					ResolvableType.forClassWithGenerics(Consumer.class,
							DefaultReactiveOAuth2AuthorizedClientManager.class));
			if (authorizedClientManagerConsumer != null) {
				authorizedClientManagerConsumer.accept(authorizedClientManager);
			}

			return authorizedClientManager;
		}

		private boolean hasDelegatingAuthorizedClientProvider(
				Collection<ReactiveOAuth2AuthorizedClientProvider> authorizedClientProviders) {
			if (authorizedClientProviders.size() != 1) {
				return false;
			}
			return authorizedClientProviders.iterator()
				.next() instanceof DelegatingReactiveOAuth2AuthorizedClientProvider;
		}

		private ReactiveOAuth2AuthorizedClientProvider getAuthorizationCodeAuthorizedClientProvider(
				Collection<ReactiveOAuth2AuthorizedClientProvider> authorizedClientProviders) {
			AuthorizationCodeReactiveOAuth2AuthorizedClientProvider authorizedClientProvider = getAuthorizedClientProviderByType(
					authorizedClientProviders, AuthorizationCodeReactiveOAuth2AuthorizedClientProvider.class);
			if (authorizedClientProvider == null) {
				authorizedClientProvider = new AuthorizationCodeReactiveOAuth2AuthorizedClientProvider();
			}

			return authorizedClientProvider;
		}

		private ReactiveOAuth2AuthorizedClientProvider getRefreshTokenAuthorizedClientProvider(
				Collection<ReactiveOAuth2AuthorizedClientProvider> authorizedClientProviders) {
			RefreshTokenReactiveOAuth2AuthorizedClientProvider authorizedClientProvider = getAuthorizedClientProviderByType(
					authorizedClientProviders, RefreshTokenReactiveOAuth2AuthorizedClientProvider.class);
			if (authorizedClientProvider == null) {
				authorizedClientProvider = new RefreshTokenReactiveOAuth2AuthorizedClientProvider();
			}

			ReactiveOAuth2AccessTokenResponseClient<OAuth2RefreshTokenGrantRequest> accessTokenResponseClient = getBeanOfType(
					ResolvableType.forClassWithGenerics(ReactiveOAuth2AccessTokenResponseClient.class,
							OAuth2RefreshTokenGrantRequest.class));
			if (accessTokenResponseClient != null) {
				authorizedClientProvider.setAccessTokenResponseClient(accessTokenResponseClient);
			}

			return authorizedClientProvider;
		}

		private ReactiveOAuth2AuthorizedClientProvider getClientCredentialsAuthorizedClientProvider(
				Collection<ReactiveOAuth2AuthorizedClientProvider> authorizedClientProviders) {
			ClientCredentialsReactiveOAuth2AuthorizedClientProvider authorizedClientProvider = getAuthorizedClientProviderByType(
					authorizedClientProviders, ClientCredentialsReactiveOAuth2AuthorizedClientProvider.class);
			if (authorizedClientProvider == null) {
				authorizedClientProvider = new ClientCredentialsReactiveOAuth2AuthorizedClientProvider();
			}

			ReactiveOAuth2AccessTokenResponseClient<OAuth2ClientCredentialsGrantRequest> accessTokenResponseClient = getBeanOfType(
					ResolvableType.forClassWithGenerics(ReactiveOAuth2AccessTokenResponseClient.class,
							OAuth2ClientCredentialsGrantRequest.class));
			if (accessTokenResponseClient != null) {
				authorizedClientProvider.setAccessTokenResponseClient(accessTokenResponseClient);
			}

			return authorizedClientProvider;
		}

		private ReactiveOAuth2AuthorizedClientProvider getPasswordAuthorizedClientProvider(
				Collection<ReactiveOAuth2AuthorizedClientProvider> authorizedClientProviders) {
			PasswordReactiveOAuth2AuthorizedClientProvider authorizedClientProvider = getAuthorizedClientProviderByType(
					authorizedClientProviders, PasswordReactiveOAuth2AuthorizedClientProvider.class);
			if (authorizedClientProvider == null) {
				authorizedClientProvider = new PasswordReactiveOAuth2AuthorizedClientProvider();
			}

			ReactiveOAuth2AccessTokenResponseClient<OAuth2PasswordGrantRequest> accessTokenResponseClient = getBeanOfType(
					ResolvableType.forClassWithGenerics(ReactiveOAuth2AccessTokenResponseClient.class,
							OAuth2PasswordGrantRequest.class));
			if (accessTokenResponseClient != null) {
				authorizedClientProvider.setAccessTokenResponseClient(accessTokenResponseClient);
			}

			return authorizedClientProvider;
		}

		private ReactiveOAuth2AuthorizedClientProvider getJwtBearerAuthorizedClientProvider(
				Collection<ReactiveOAuth2AuthorizedClientProvider> authorizedClientProviders) {
			JwtBearerReactiveOAuth2AuthorizedClientProvider authorizedClientProvider = getAuthorizedClientProviderByType(
					authorizedClientProviders, JwtBearerReactiveOAuth2AuthorizedClientProvider.class);

			ReactiveOAuth2AccessTokenResponseClient<JwtBearerGrantRequest> accessTokenResponseClient = getBeanOfType(
					ResolvableType.forClassWithGenerics(ReactiveOAuth2AccessTokenResponseClient.class,
							JwtBearerGrantRequest.class));
			if (accessTokenResponseClient != null) {
				if (authorizedClientProvider == null) {
					authorizedClientProvider = new JwtBearerReactiveOAuth2AuthorizedClientProvider();
				}

				authorizedClientProvider.setAccessTokenResponseClient(accessTokenResponseClient);
			}

			return authorizedClientProvider;
		}

		private ReactiveOAuth2AuthorizedClientProvider getTokenExchangeAuthorizedClientProvider(
				Collection<ReactiveOAuth2AuthorizedClientProvider> authorizedClientProviders) {
			TokenExchangeReactiveOAuth2AuthorizedClientProvider authorizedClientProvider = getAuthorizedClientProviderByType(
					authorizedClientProviders, TokenExchangeReactiveOAuth2AuthorizedClientProvider.class);

			ReactiveOAuth2AccessTokenResponseClient<TokenExchangeGrantRequest> accessTokenResponseClient = getBeanOfType(
					ResolvableType.forClassWithGenerics(ReactiveOAuth2AccessTokenResponseClient.class,
							TokenExchangeGrantRequest.class));
			if (accessTokenResponseClient != null) {
				if (authorizedClientProvider == null) {
					authorizedClientProvider = new TokenExchangeReactiveOAuth2AuthorizedClientProvider();
				}

				authorizedClientProvider.setAccessTokenResponseClient(accessTokenResponseClient);
			}

			return authorizedClientProvider;
		}

		private List<ReactiveOAuth2AuthorizedClientProvider> getAdditionalAuthorizedClientProviders(
				Collection<ReactiveOAuth2AuthorizedClientProvider> authorizedClientProviders) {
			List<ReactiveOAuth2AuthorizedClientProvider> additionalAuthorizedClientProviders = new ArrayList<>(
					authorizedClientProviders);
			additionalAuthorizedClientProviders
				.removeIf((provider) -> KNOWN_AUTHORIZED_CLIENT_PROVIDERS.contains(provider.getClass()));
			return additionalAuthorizedClientProviders;
		}

		private <T extends ReactiveOAuth2AuthorizedClientProvider> T getAuthorizedClientProviderByType(
				Collection<ReactiveOAuth2AuthorizedClientProvider> authorizedClientProviders, Class<T> providerClass) {
			T authorizedClientProvider = null;
			for (ReactiveOAuth2AuthorizedClientProvider current : authorizedClientProviders) {
				if (providerClass.isInstance(current)) {
					assertAuthorizedClientProviderIsNull(authorizedClientProvider);
					authorizedClientProvider = providerClass.cast(current);
				}
			}
			return authorizedClientProvider;
		}

		private static void assertAuthorizedClientProviderIsNull(
				ReactiveOAuth2AuthorizedClientProvider authorizedClientProvider) {
			if (authorizedClientProvider != null) {
				// @formatter:off
				throw new BeanInitializationException(String.format(
						"Unable to create a %s bean. Expected one bean of type %s, but found multiple. " +
						"Please consider defining only a single bean of this type, or define a %s bean yourself.",
						ReactiveOAuth2AuthorizedClientManager.class.getName(),
						authorizedClientProvider.getClass().getName(),
						ReactiveOAuth2AuthorizedClientManager.class.getName()));
				// @formatter:on
			}
		}

		private <T> String[] getBeanNamesForType(Class<T> beanClass) {
			return BeanFactoryUtils.beanNamesForTypeIncludingAncestors(this.beanFactory, beanClass, true, true);
		}

		private <T> T getBeanOfType(ResolvableType resolvableType) {
			ObjectProvider<T> objectProvider = this.beanFactory.getBeanProvider(resolvableType, true);
			return objectProvider.getIfAvailable();
		}

	}

}
