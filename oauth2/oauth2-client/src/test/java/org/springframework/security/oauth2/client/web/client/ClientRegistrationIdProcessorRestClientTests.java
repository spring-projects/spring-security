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
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.support.RestClientAdapter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.given;

/**
 * Runs tests of {@link ClientRegistrationIdProcessor} with {@link RestClient} to ensure
 * that all the parts work together properly.
 *
 * @author Rob Winch
 * @since 7.0
 */
@ExtendWith(MockitoExtension.class)
class ClientRegistrationIdProcessorRestClientTests extends AbstractMockServerClientRegistrationIdProcessorTests {

	@Mock
	private OAuth2AuthorizedClientManager authorizedClientManager;

	@Test
	void clientRegistrationIdProcessorWorksWithRestClientAdapter() throws InterruptedException {
		OAuth2ClientHttpRequestInterceptor interceptor = new OAuth2ClientHttpRequestInterceptor(
				this.authorizedClientManager);
		RestClient.Builder builder = RestClient.builder().requestInterceptor(interceptor).baseUrl(this.baseUrl);

		ArgumentCaptor<OAuth2AuthorizeRequest> authorizeRequest = ArgumentCaptor.forClass(OAuth2AuthorizeRequest.class);
		given(this.authorizedClientManager.authorize(authorizeRequest.capture())).willReturn(authorizedClient);

		testWithAdapter(RestClientAdapter.create(builder.build()));

		assertThat(authorizeRequest.getValue().getClientRegistrationId()).isEqualTo(REGISTRATION_ID);
	}

}
