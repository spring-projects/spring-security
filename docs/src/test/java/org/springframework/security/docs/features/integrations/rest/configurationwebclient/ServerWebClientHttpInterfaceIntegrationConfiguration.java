/*
 * Copyright 2002-2025 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain clients copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.docs.features.integrations.rest.configurationwebclient;

import okhttp3.mockwebserver.MockWebServer;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.docs.features.integrations.rest.clientregistrationid.UserService;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.client.support.OAuth2RestClientHttpServiceGroupConfigurer;
import org.springframework.security.oauth2.client.web.reactive.function.client.support.OAuth2WebClientHttpServiceGroupConfigurer;
import org.springframework.web.reactive.function.client.support.WebClientHttpServiceGroupConfigurer;
import org.springframework.web.service.registry.HttpServiceGroup;
import org.springframework.web.service.registry.ImportHttpServices;

import static org.mockito.Mockito.mock;

/**
 * Documentation for {@link OAuth2RestClientHttpServiceGroupConfigurer}.
 * @author Rob Winch
 */
@Configuration(proxyBeanMethods = false)
@ImportHttpServices(types = UserService.class, clientType = HttpServiceGroup.ClientType.WEB_CLIENT)
public class ServerWebClientHttpInterfaceIntegrationConfiguration {

	// tag::config[]
	@Bean
	OAuth2WebClientHttpServiceGroupConfigurer securityConfigurer(
			ReactiveOAuth2AuthorizedClientManager manager) {
		return OAuth2WebClientHttpServiceGroupConfigurer.from(manager);
	}
	// end::config[]

	@Bean
	ReactiveOAuth2AuthorizedClientManager authorizedClientManager() {
		return mock(ReactiveOAuth2AuthorizedClientManager.class);
	}

	@Bean
	WebClientHttpServiceGroupConfigurer groupConfigurer(MockWebServer server) {
		return groups -> {
			String baseUrl = server.url("").toString();
			groups
				.forEachClient((group, builder) -> builder
				.baseUrl(baseUrl)
				.defaultHeader("Accept", "application/vnd.github.v3+json"));
		};
	}

	@Bean
	MockWebServer mockServer() {
		return new MockWebServer();
	}
}
