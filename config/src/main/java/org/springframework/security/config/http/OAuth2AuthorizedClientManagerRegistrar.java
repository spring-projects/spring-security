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

package org.springframework.security.config.http;

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
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.BeanDefinitionRegistryPostProcessor;
import org.springframework.context.annotation.AnnotationBeanNameGenerator;
import org.springframework.core.ResolvableType;
import org.springframework.security.oauth2.client.AuthorizationCodeOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.ClientCredentialsOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.DelegatingOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.JwtBearerOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.PasswordOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.RefreshTokenOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.TokenExchangeOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.endpoint.JwtBearerGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2ClientCredentialsGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2PasswordGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequest;
import org.springframework.security.oauth2.client.endpoint.TokenExchangeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;

/**
 * A registrar for registering the default {@link OAuth2AuthorizedClientManager} bean
 * definition, if not already present.
 * <p>
 * Note: This class is a direct copy of
 * {@link org.springframework.security.config.annotation.web.configuration.OAuth2ClientConfiguration.OAuth2AuthorizedClientManagerRegistrar}.
 *
 * @author Joe Grandja
 * @author Steve Riesenberg
 * @since 6.2.0
 */
final class OAuth2AuthorizedClientManagerRegistrar implements BeanDefinitionRegistryPostProcessor, BeanFactoryAware {

	static final String BEAN_NAME = "authorizedClientManagerRegistrar";

	static final String FACTORY_METHOD_NAME = "getAuthorizedClientManager";

	// @formatter:off
	private static final Set<Class<?>> KNOWN_AUTHORIZED_CLIENT_PROVIDERS = Set.of(
			AuthorizationCodeOAuth2AuthorizedClientProvider.class,
			RefreshTokenOAuth2AuthorizedClientProvider.class,
			ClientCredentialsOAuth2AuthorizedClientProvider.class,
			PasswordOAuth2AuthorizedClientProvider.class,
			JwtBearerOAuth2AuthorizedClientProvider.class,
			TokenExchangeOAuth2AuthorizedClientProvider.class
	);
	// @formatter:on

	private final AnnotationBeanNameGenerator beanNameGenerator = new AnnotationBeanNameGenerator();

	private ListableBeanFactory beanFactory;

	@Override
	public void postProcessBeanDefinitionRegistry(BeanDefinitionRegistry registry) throws BeansException {
		if (getBeanNamesForType(OAuth2AuthorizedClientManager.class).length != 0
				|| getBeanNamesForType(ClientRegistrationRepository.class).length != 1
				|| getBeanNamesForType(OAuth2AuthorizedClientRepository.class).length != 1) {
			return;
		}

		BeanDefinition beanDefinition = BeanDefinitionBuilder.rootBeanDefinition(OAuth2AuthorizedClientManager.class)
			.setFactoryMethodOnBean(FACTORY_METHOD_NAME, BEAN_NAME)
			.getBeanDefinition();

		registry.registerBeanDefinition(this.beanNameGenerator.generateBeanName(beanDefinition, registry),
				beanDefinition);
	}

	@Override
	public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {
	}

	@Override
	public void setBeanFactory(BeanFactory beanFactory) throws BeansException {
		this.beanFactory = (ListableBeanFactory) beanFactory;
	}

	private OAuth2AuthorizedClientManager getAuthorizedClientManager() {
		ClientRegistrationRepository clientRegistrationRepository = BeanFactoryUtils
			.beanOfTypeIncludingAncestors(this.beanFactory, ClientRegistrationRepository.class, true, true);

		OAuth2AuthorizedClientRepository authorizedClientRepository = BeanFactoryUtils
			.beanOfTypeIncludingAncestors(this.beanFactory, OAuth2AuthorizedClientRepository.class, true, true);

		Collection<OAuth2AuthorizedClientProvider> authorizedClientProviderBeans = BeanFactoryUtils
			.beansOfTypeIncludingAncestors(this.beanFactory, OAuth2AuthorizedClientProvider.class, true, true)
			.values();

		OAuth2AuthorizedClientProvider authorizedClientProvider;
		if (hasDelegatingAuthorizedClientProvider(authorizedClientProviderBeans)) {
			authorizedClientProvider = authorizedClientProviderBeans.iterator().next();
		}
		else {
			List<OAuth2AuthorizedClientProvider> authorizedClientProviders = new ArrayList<>();
			authorizedClientProviders.add(getAuthorizationCodeAuthorizedClientProvider(authorizedClientProviderBeans));
			authorizedClientProviders.add(getRefreshTokenAuthorizedClientProvider(authorizedClientProviderBeans));
			authorizedClientProviders.add(getClientCredentialsAuthorizedClientProvider(authorizedClientProviderBeans));
			authorizedClientProviders.add(getPasswordAuthorizedClientProvider(authorizedClientProviderBeans));

			OAuth2AuthorizedClientProvider jwtBearerAuthorizedClientProvider = getJwtBearerAuthorizedClientProvider(
					authorizedClientProviderBeans);
			if (jwtBearerAuthorizedClientProvider != null) {
				authorizedClientProviders.add(jwtBearerAuthorizedClientProvider);
			}

			OAuth2AuthorizedClientProvider tokenExchangeAuthorizedClientProvider = getTokenExchangeAuthorizedClientProvider(
					authorizedClientProviderBeans);
			if (tokenExchangeAuthorizedClientProvider != null) {
				authorizedClientProviders.add(tokenExchangeAuthorizedClientProvider);
			}

			authorizedClientProviders.addAll(getAdditionalAuthorizedClientProviders(authorizedClientProviderBeans));
			authorizedClientProvider = new DelegatingOAuth2AuthorizedClientProvider(authorizedClientProviders);
		}

		DefaultOAuth2AuthorizedClientManager authorizedClientManager = new DefaultOAuth2AuthorizedClientManager(
				clientRegistrationRepository, authorizedClientRepository);
		authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);

		Consumer<DefaultOAuth2AuthorizedClientManager> authorizedClientManagerConsumer = getBeanOfType(
				ResolvableType.forClassWithGenerics(Consumer.class, DefaultOAuth2AuthorizedClientManager.class));
		if (authorizedClientManagerConsumer != null) {
			authorizedClientManagerConsumer.accept(authorizedClientManager);
		}

		return authorizedClientManager;
	}

	private boolean hasDelegatingAuthorizedClientProvider(
			Collection<OAuth2AuthorizedClientProvider> authorizedClientProviders) {
		if (authorizedClientProviders.size() != 1) {
			return false;
		}
		return authorizedClientProviders.iterator().next() instanceof DelegatingOAuth2AuthorizedClientProvider;
	}

	private OAuth2AuthorizedClientProvider getAuthorizationCodeAuthorizedClientProvider(
			Collection<OAuth2AuthorizedClientProvider> authorizedClientProviders) {
		AuthorizationCodeOAuth2AuthorizedClientProvider authorizedClientProvider = getAuthorizedClientProviderByType(
				authorizedClientProviders, AuthorizationCodeOAuth2AuthorizedClientProvider.class);
		if (authorizedClientProvider == null) {
			authorizedClientProvider = new AuthorizationCodeOAuth2AuthorizedClientProvider();
		}

		return authorizedClientProvider;
	}

	private OAuth2AuthorizedClientProvider getRefreshTokenAuthorizedClientProvider(
			Collection<OAuth2AuthorizedClientProvider> authorizedClientProviders) {
		RefreshTokenOAuth2AuthorizedClientProvider authorizedClientProvider = getAuthorizedClientProviderByType(
				authorizedClientProviders, RefreshTokenOAuth2AuthorizedClientProvider.class);
		if (authorizedClientProvider == null) {
			authorizedClientProvider = new RefreshTokenOAuth2AuthorizedClientProvider();
		}

		OAuth2AccessTokenResponseClient<OAuth2RefreshTokenGrantRequest> accessTokenResponseClient = getBeanOfType(
				ResolvableType.forClassWithGenerics(OAuth2AccessTokenResponseClient.class,
						OAuth2RefreshTokenGrantRequest.class));
		if (accessTokenResponseClient != null) {
			authorizedClientProvider.setAccessTokenResponseClient(accessTokenResponseClient);
		}

		return authorizedClientProvider;
	}

	private OAuth2AuthorizedClientProvider getClientCredentialsAuthorizedClientProvider(
			Collection<OAuth2AuthorizedClientProvider> authorizedClientProviders) {
		ClientCredentialsOAuth2AuthorizedClientProvider authorizedClientProvider = getAuthorizedClientProviderByType(
				authorizedClientProviders, ClientCredentialsOAuth2AuthorizedClientProvider.class);
		if (authorizedClientProvider == null) {
			authorizedClientProvider = new ClientCredentialsOAuth2AuthorizedClientProvider();
		}

		OAuth2AccessTokenResponseClient<OAuth2ClientCredentialsGrantRequest> accessTokenResponseClient = getBeanOfType(
				ResolvableType.forClassWithGenerics(OAuth2AccessTokenResponseClient.class,
						OAuth2ClientCredentialsGrantRequest.class));
		if (accessTokenResponseClient != null) {
			authorizedClientProvider.setAccessTokenResponseClient(accessTokenResponseClient);
		}

		return authorizedClientProvider;
	}

	private OAuth2AuthorizedClientProvider getPasswordAuthorizedClientProvider(
			Collection<OAuth2AuthorizedClientProvider> authorizedClientProviders) {
		PasswordOAuth2AuthorizedClientProvider authorizedClientProvider = getAuthorizedClientProviderByType(
				authorizedClientProviders, PasswordOAuth2AuthorizedClientProvider.class);
		if (authorizedClientProvider == null) {
			authorizedClientProvider = new PasswordOAuth2AuthorizedClientProvider();
		}

		OAuth2AccessTokenResponseClient<OAuth2PasswordGrantRequest> accessTokenResponseClient = getBeanOfType(
				ResolvableType.forClassWithGenerics(OAuth2AccessTokenResponseClient.class,
						OAuth2PasswordGrantRequest.class));
		if (accessTokenResponseClient != null) {
			authorizedClientProvider.setAccessTokenResponseClient(accessTokenResponseClient);
		}

		return authorizedClientProvider;
	}

	private OAuth2AuthorizedClientProvider getJwtBearerAuthorizedClientProvider(
			Collection<OAuth2AuthorizedClientProvider> authorizedClientProviders) {
		JwtBearerOAuth2AuthorizedClientProvider authorizedClientProvider = getAuthorizedClientProviderByType(
				authorizedClientProviders, JwtBearerOAuth2AuthorizedClientProvider.class);

		OAuth2AccessTokenResponseClient<JwtBearerGrantRequest> accessTokenResponseClient = getBeanOfType(ResolvableType
			.forClassWithGenerics(OAuth2AccessTokenResponseClient.class, JwtBearerGrantRequest.class));
		if (accessTokenResponseClient != null) {
			if (authorizedClientProvider == null) {
				authorizedClientProvider = new JwtBearerOAuth2AuthorizedClientProvider();
			}

			authorizedClientProvider.setAccessTokenResponseClient(accessTokenResponseClient);
		}

		return authorizedClientProvider;
	}

	private OAuth2AuthorizedClientProvider getTokenExchangeAuthorizedClientProvider(
			Collection<OAuth2AuthorizedClientProvider> authorizedClientProviders) {
		TokenExchangeOAuth2AuthorizedClientProvider authorizedClientProvider = getAuthorizedClientProviderByType(
				authorizedClientProviders, TokenExchangeOAuth2AuthorizedClientProvider.class);

		OAuth2AccessTokenResponseClient<TokenExchangeGrantRequest> accessTokenResponseClient = getBeanOfType(
				ResolvableType.forClassWithGenerics(OAuth2AccessTokenResponseClient.class,
						TokenExchangeGrantRequest.class));
		if (accessTokenResponseClient != null) {
			if (authorizedClientProvider == null) {
				authorizedClientProvider = new TokenExchangeOAuth2AuthorizedClientProvider();
			}

			authorizedClientProvider.setAccessTokenResponseClient(accessTokenResponseClient);
		}

		return authorizedClientProvider;
	}

	private List<OAuth2AuthorizedClientProvider> getAdditionalAuthorizedClientProviders(
			Collection<OAuth2AuthorizedClientProvider> authorizedClientProviders) {
		List<OAuth2AuthorizedClientProvider> additionalAuthorizedClientProviders = new ArrayList<>(
				authorizedClientProviders);
		additionalAuthorizedClientProviders
			.removeIf((provider) -> KNOWN_AUTHORIZED_CLIENT_PROVIDERS.contains(provider.getClass()));
		return additionalAuthorizedClientProviders;
	}

	private <T extends OAuth2AuthorizedClientProvider> T getAuthorizedClientProviderByType(
			Collection<OAuth2AuthorizedClientProvider> authorizedClientProviders, Class<T> providerClass) {
		T authorizedClientProvider = null;
		for (OAuth2AuthorizedClientProvider current : authorizedClientProviders) {
			if (providerClass.isInstance(current)) {
				assertAuthorizedClientProviderIsNull(authorizedClientProvider);
				authorizedClientProvider = providerClass.cast(current);
			}
		}
		return authorizedClientProvider;
	}

	private static void assertAuthorizedClientProviderIsNull(OAuth2AuthorizedClientProvider authorizedClientProvider) {
		if (authorizedClientProvider != null) {
			// @formatter:off
			throw new BeanInitializationException(String.format(
					"Unable to create an %s bean. Expected one bean of type %s, but found multiple. " +
					"Please consider defining only a single bean of this type, or define an %s bean yourself.",
					OAuth2AuthorizedClientManager.class.getName(),
					authorizedClientProvider.getClass().getName(),
					OAuth2AuthorizedClientManager.class.getName()));
			// @formatter:on
		}
	}

	private <T> String[] getBeanNamesForType(Class<T> beanClass) {
		return BeanFactoryUtils.beanNamesForTypeIncludingAncestors(this.beanFactory, beanClass, false, false);
	}

	private <T> T getBeanOfType(ResolvableType resolvableType) {
		ObjectProvider<T> objectProvider = this.beanFactory.getBeanProvider(resolvableType, true);
		return objectProvider.getIfAvailable();
	}

}
