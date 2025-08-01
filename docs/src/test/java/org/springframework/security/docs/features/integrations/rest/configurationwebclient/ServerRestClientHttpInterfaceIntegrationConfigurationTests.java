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

package org.springframework.security.docs.features.integrations.rest.configurationwebclient;

import java.time.Duration;
import java.time.Instant;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import reactor.core.publisher.Mono;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.docs.features.integrations.rest.clientregistrationid.UserService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;

/**
 * Demonstrates configuring RestClient with interface based proxy clients.
 * @author Rob Winch
 */
@ExtendWith(SpringExtension.class)
@ContextConfiguration(classes = ServerWebClientHttpInterfaceIntegrationConfiguration.class)
class ServerRestClientHttpInterfaceIntegrationConfigurationTests {

	@Test
	void getAuthenticatedUser(@Autowired MockWebServer webServer, @Autowired ReactiveOAuth2AuthorizedClientManager authorizedClients, @Autowired UserService users)
			throws InterruptedException {
		ClientRegistration registration = CommonOAuth2Provider.GITHUB.getBuilder("github").clientId("github").build();

		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plus(Duration.ofMinutes(5));
		OAuth2AccessToken token = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "1234",
				issuedAt, expiresAt);
		OAuth2AuthorizedClient result = new OAuth2AuthorizedClient(registration, "rob", token);
		given(authorizedClients.authorize(any())).willReturn(Mono.just(result));

		webServer.enqueue(new MockResponse().addHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE).setBody(
				"""
				{"login": "rob_winch", "id": 1234, "name": "Rob Winch" }
				"""));

		users.getAuthenticatedUser();

		assertThat(webServer.takeRequest().getHeader(HttpHeaders.AUTHORIZATION)).isEqualTo("Bearer " + token.getTokenValue());
	}

}
