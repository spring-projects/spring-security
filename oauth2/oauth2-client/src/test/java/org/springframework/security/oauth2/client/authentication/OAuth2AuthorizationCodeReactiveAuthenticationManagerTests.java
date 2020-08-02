/*
 * Copyright 2002-2019 the original author or authors.
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

package org.springframework.security.oauth2.client.authentication;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import reactor.core.publisher.Mono;

import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.endpoint.ReactiveOAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.oauth2.core.endpoint.TestOAuth2AccessTokenResponses;
import org.springframework.security.oauth2.core.endpoint.TestOAuth2AuthorizationRequests;
import org.springframework.security.oauth2.core.endpoint.TestOAuth2AuthorizationResponses;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;

/**
 * @author Rob Winch
 * @since 5.1
 */
@RunWith(MockitoJUnitRunner.class)
public class OAuth2AuthorizationCodeReactiveAuthenticationManagerTests {

	@Mock
	private ReactiveOAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient;

	private OAuth2AuthorizationCodeReactiveAuthenticationManager manager;

	private ClientRegistration.Builder registration = TestClientRegistrations.clientRegistration();

	private OAuth2AuthorizationRequest.Builder authorizationRequest = TestOAuth2AuthorizationRequests.request();

	private OAuth2AuthorizationResponse.Builder authorizationResponse = TestOAuth2AuthorizationResponses.success();

	private OAuth2AccessTokenResponse.Builder tokenResponse = TestOAuth2AccessTokenResponses.accessTokenResponse();

	@Before
	public void setup() {
		this.manager = new OAuth2AuthorizationCodeReactiveAuthenticationManager(this.accessTokenResponseClient);
	}

	@Test
	public void authenticateWhenErrorThenOAuth2AuthorizationException() {
		this.authorizationResponse = TestOAuth2AuthorizationResponses.error();
		assertThatCode(() -> authenticate()).isInstanceOf(OAuth2AuthorizationException.class);
	}

	@Test
	public void authenticateWhenStateNotEqualThenOAuth2AuthorizationException() {
		this.authorizationRequest.state("notequal");
		assertThatCode(() -> authenticate()).isInstanceOf(OAuth2AuthorizationException.class);
	}

	@Test
	public void authenticateWhenValidThenSuccess() {
		given(this.accessTokenResponseClient.getTokenResponse(any())).willReturn(Mono.just(this.tokenResponse.build()));
		OAuth2AuthorizationCodeAuthenticationToken result = authenticate();
		assertThat(result).isNotNull();
	}

	@Test
	public void authenticateWhenEmptyThenEmpty() {
		given(this.accessTokenResponseClient.getTokenResponse(any())).willReturn(Mono.empty());
		OAuth2AuthorizationCodeAuthenticationToken result = authenticate();
		assertThat(result).isNull();
	}

	@Test
	public void authenticateWhenOAuth2AuthorizationExceptionThenOAuth2AuthorizationException() {
		given(this.accessTokenResponseClient.getTokenResponse(any()))
				.willReturn(Mono.error(() -> new OAuth2AuthorizationException(new OAuth2Error("error"))));
		assertThatCode(() -> authenticate()).isInstanceOf(OAuth2AuthorizationException.class);
	}

	private OAuth2AuthorizationCodeAuthenticationToken authenticate() {
		OAuth2AuthorizationExchange exchange = new OAuth2AuthorizationExchange(this.authorizationRequest.build(),
				this.authorizationResponse.build());
		OAuth2AuthorizationCodeAuthenticationToken token = new OAuth2AuthorizationCodeAuthenticationToken(
				this.registration.build(), exchange);
		return (OAuth2AuthorizationCodeAuthenticationToken) this.manager.authenticate(token).block();
	}

}
