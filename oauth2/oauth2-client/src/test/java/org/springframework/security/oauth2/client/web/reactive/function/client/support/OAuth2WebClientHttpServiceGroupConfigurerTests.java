/*
 * Copyright 2002-2025 the original author or authors.
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

package org.springframework.security.oauth2.client.web.reactive.function.client.support;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.client.ClientRegistrationIdProcessor;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.service.invoker.HttpServiceProxyFactory;
import org.springframework.web.service.registry.HttpServiceGroupConfigurer;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;

/**
 * Tests {@link OAuth2WebClientHttpServiceGroupConfigurer}.
 *
 * @author Rob Winch
 */
@ExtendWith(MockitoExtension.class)
class OAuth2WebClientHttpServiceGroupConfigurerTests {

	@Mock
	private OAuth2AuthorizedClientManager authoriedClientManager;

	@Mock
	private HttpServiceGroupConfigurer.Groups<WebClient.Builder> groups;

	@Captor
	ArgumentCaptor<HttpServiceGroupConfigurer.ProxyFactoryCallback> forProxyFactory;

	@Mock
	private HttpServiceProxyFactory.Builder factoryBuilder;

	@Captor
	private ArgumentCaptor<HttpServiceGroupConfigurer.ClientCallback<WebClient.Builder>> configureClient;

	@Mock
	private WebClient.Builder clientBuilder;

	@Test
	void configureGroupsConfigureProxyFactory() {

		OAuth2WebClientHttpServiceGroupConfigurer configurer = OAuth2WebClientHttpServiceGroupConfigurer
			.from(this.authoriedClientManager);

		configurer.configureGroups(this.groups);
		verify(this.groups).forEachProxyFactory(this.forProxyFactory.capture());

		this.forProxyFactory.getValue().withProxyFactory(null, this.factoryBuilder);

		verify(this.factoryBuilder).httpRequestValuesProcessor(ClientRegistrationIdProcessor.DEFAULT_INSTANCE);
	}

	@Test
	void configureGroupsConfigureClient() {
		OAuth2WebClientHttpServiceGroupConfigurer configurer = OAuth2WebClientHttpServiceGroupConfigurer
			.from(this.authoriedClientManager);

		configurer.configureGroups(this.groups);
		verify(this.groups).forEachClient(this.configureClient.capture());

		this.configureClient.getValue().withClient(null, this.clientBuilder);

		verify(this.clientBuilder).filter(any(ExchangeFilterFunction.class));
	}

}
