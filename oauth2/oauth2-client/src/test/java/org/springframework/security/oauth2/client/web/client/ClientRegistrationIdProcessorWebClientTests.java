/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.oauth2.client.web.client;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;

import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServerOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.support.WebClientAdapter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

/**
 * Runs tests for {@link ClientRegistrationIdProcessor} with {@link WebClient} to ensure
 * that all the parts work together properly.
 *
 * @author Rob Winch
 * @since 7.0
 */
@ExtendWith(MockitoExtension.class)
class ClientRegistrationIdProcessorWebClientTests extends AbstractMockServerClientRegistrationIdProcessorTests {

	@Test
	void clientRegistrationIdProcessorWorksWithReactiveWebClient() throws InterruptedException {
		ReactiveOAuth2AuthorizedClientManager authorizedClientManager = mock(
				ReactiveOAuth2AuthorizedClientManager.class);
		ServerOAuth2AuthorizedClientExchangeFilterFunction oauth2Client = new ServerOAuth2AuthorizedClientExchangeFilterFunction(
				authorizedClientManager);

		WebClient.Builder builder = WebClient.builder().filter(oauth2Client).baseUrl(this.baseUrl);

		ArgumentCaptor<OAuth2AuthorizeRequest> authorizeRequest = ArgumentCaptor.forClass(OAuth2AuthorizeRequest.class);
		given(authorizedClientManager.authorize(authorizeRequest.capture()))
			.willReturn(Mono.just(this.authorizedClient));

		testWithAdapter(WebClientAdapter.create(builder.build()));

		assertThat(authorizeRequest.getValue().getClientRegistrationId()).isEqualTo(REGISTRATION_ID);
	}

	@Test
	void clientRegistrationIdProcessorWorksWithServletWebClient() throws InterruptedException {
		OAuth2AuthorizedClientManager authorizedClientManager = mock(OAuth2AuthorizedClientManager.class);

		ServletOAuth2AuthorizedClientExchangeFilterFunction oauth2Client = new ServletOAuth2AuthorizedClientExchangeFilterFunction(
				authorizedClientManager);

		WebClient.Builder builder = WebClient.builder().filter(oauth2Client).baseUrl(this.baseUrl);

		ArgumentCaptor<OAuth2AuthorizeRequest> authorizeRequest = ArgumentCaptor.forClass(OAuth2AuthorizeRequest.class);
		given(authorizedClientManager.authorize(authorizeRequest.capture())).willReturn(this.authorizedClient);

		testWithAdapter(WebClientAdapter.create(builder.build()));

		assertThat(authorizeRequest.getValue().getClientRegistrationId()).isEqualTo(REGISTRATION_ID);
	}

}
