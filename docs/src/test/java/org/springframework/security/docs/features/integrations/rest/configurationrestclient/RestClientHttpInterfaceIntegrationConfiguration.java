/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.docs.features.integrations.rest.configurationrestclient;

import okhttp3.mockwebserver.MockWebServer;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.docs.features.integrations.rest.clientregistrationid.UserService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.client.support.OAuth2RestClientHttpServiceGroupConfigurer;
import org.springframework.web.client.support.RestClientHttpServiceGroupConfigurer;
import org.springframework.web.service.registry.ImportHttpServices;

import static org.mockito.Mockito.mock;

/**
 * Documentation for {@link OAuth2RestClientHttpServiceGroupConfigurer}.
 * @author Rob Winch
 */
@Configuration(proxyBeanMethods = false)
@ImportHttpServices(types = UserService.class)
public class RestClientHttpInterfaceIntegrationConfiguration {

	// tag::config[]
	@Bean
	OAuth2RestClientHttpServiceGroupConfigurer securityConfigurer(
			OAuth2AuthorizedClientManager manager) {
		return OAuth2RestClientHttpServiceGroupConfigurer.from(manager);
	}
	// end::config[]

	@Bean
	OAuth2AuthorizedClientManager authorizedClientManager() {
		return mock(OAuth2AuthorizedClientManager.class);
	}

	@Bean
	RestClientHttpServiceGroupConfigurer groupConfigurer(MockWebServer server) {
		return groups -> {

			groups
				.forEachClient((group, builder) -> builder
				.baseUrl(server.url("").toString())
				.defaultHeader("Accept", "application/vnd.github.v3+json"));
		};
	}

	@Bean
	MockWebServer mockServer() {
		return new MockWebServer();
	}
}
