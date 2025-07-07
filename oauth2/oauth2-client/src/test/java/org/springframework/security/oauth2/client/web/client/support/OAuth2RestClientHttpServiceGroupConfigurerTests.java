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

package org.springframework.security.oauth2.client.web.client.support;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.client.ClientRegistrationIdProcessor;
import org.springframework.security.oauth2.client.web.client.OAuth2ClientHttpRequestInterceptor;
import org.springframework.web.client.RestClient;
import org.springframework.web.service.invoker.HttpServiceProxyFactory;
import org.springframework.web.service.registry.HttpServiceGroupConfigurer;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;

/**
 * Tests {@link OAuth2RestClientHttpServiceGroupConfigurer}.
 *
 * @author Rob Winch
 */
@ExtendWith(MockitoExtension.class)
class OAuth2RestClientHttpServiceGroupConfigurerTests {

	@Mock
	private OAuth2AuthorizedClientManager authoriedClientManager;

	@Mock
	private HttpServiceGroupConfigurer.Groups<RestClient.Builder> groups;

	@Captor
	ArgumentCaptor<HttpServiceGroupConfigurer.ProxyFactoryCallback> forProxyFactory;

	@Mock
	private HttpServiceProxyFactory.Builder factoryBuilder;

	@Captor
	private ArgumentCaptor<HttpServiceGroupConfigurer.ClientCallback<RestClient.Builder>> configureClient;

	@Mock
	private RestClient.Builder clientBuilder;

	@Test
	void configureGroupsConfigureProxyFactory() {

		OAuth2RestClientHttpServiceGroupConfigurer configurer = OAuth2RestClientHttpServiceGroupConfigurer
			.from(this.authoriedClientManager);

		configurer.configureGroups(this.groups);
		verify(this.groups).forEachProxyFactory(this.forProxyFactory.capture());

		this.forProxyFactory.getValue().withProxyFactory(null, this.factoryBuilder);

		verify(this.factoryBuilder).httpRequestValuesProcessor(ClientRegistrationIdProcessor.DEFAULT_INSTANCE);
	}

	@Test
	void configureGroupsConfigureClient() {
		OAuth2RestClientHttpServiceGroupConfigurer configurer = OAuth2RestClientHttpServiceGroupConfigurer
			.from(this.authoriedClientManager);

		configurer.configureGroups(this.groups);
		verify(this.groups).forEachClient(this.configureClient.capture());

		this.configureClient.getValue().withClient(null, this.clientBuilder);

		verify(this.clientBuilder).requestInterceptor(any(OAuth2ClientHttpRequestInterceptor.class));
	}

}
