/*
 * Copyright 2002-2020 the original author or authors.
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

package org.springframework.security.oauth2.client.web.server;

import java.util.Collections;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import reactor.core.publisher.Mono;

import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;

/**
 * @author Rob Winch
 * @since 5.1
 */
@RunWith(MockitoJUnitRunner.class)
public class ServerOAuth2AuthorizationCodeAuthenticationTokenConverterTests {

	@Mock
	private ReactiveClientRegistrationRepository clientRegistrationRepository;

	@Mock
	private ServerAuthorizationRequestRepository authorizationRequestRepository;

	private String clientRegistrationId = "github";

	// @formatter:off
	private ClientRegistration clientRegistration = ClientRegistration.withRegistrationId(this.clientRegistrationId)
			.redirectUri("{baseUrl}/{action}/oauth2/code/{registrationId}")
			.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.scope("read:user")
			.authorizationUri("https://github.com/login/oauth/authorize")
			.tokenUri("https://github.com/login/oauth/access_token")
			.userInfoUri("https://api.github.com/user")
			.userNameAttributeName("id")
			.clientName("GitHub")
			.clientId("clientId")
			.clientSecret("clientSecret")
			.build();
	// @formatter:on

	// @formatter:off
	private OAuth2AuthorizationRequest.Builder authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
			.authorizationUri("https://example.com/oauth2/authorize")
			.clientId("client-id")
			.redirectUri("http://localhost/client-1")
			.state("state")
			.attributes(Collections.singletonMap(OAuth2ParameterNames.REGISTRATION_ID, this.clientRegistrationId));
	// @formatter:on

	private final MockServerHttpRequest.BaseBuilder<?> request = MockServerHttpRequest.get("/");

	private ServerOAuth2AuthorizationCodeAuthenticationTokenConverter converter;

	@Before
	public void setup() {
		this.converter = new ServerOAuth2AuthorizationCodeAuthenticationTokenConverter(
				this.clientRegistrationRepository);
		this.converter.setAuthorizationRequestRepository(this.authorizationRequestRepository);
	}

	@Test
	public void applyWhenAuthorizationRequestEmptyThenOAuth2AuthorizationException() {
		given(this.authorizationRequestRepository.removeAuthorizationRequest(any())).willReturn(Mono.empty());
		assertThatExceptionOfType(OAuth2AuthorizationException.class).isThrownBy(() -> applyConverter());
	}

	@Test
	public void applyWhenAttributesMissingThenOAuth2AuthorizationException() {
		this.authorizationRequest.attributes(Map::clear);
		given(this.authorizationRequestRepository.removeAuthorizationRequest(any()))
				.willReturn(Mono.just(this.authorizationRequest.build()));
		assertThatExceptionOfType(OAuth2AuthorizationException.class).isThrownBy(() -> applyConverter())
				.withMessageContaining(
						ServerOAuth2AuthorizationCodeAuthenticationTokenConverter.CLIENT_REGISTRATION_NOT_FOUND_ERROR_CODE);
	}

	@Test
	public void applyWhenClientRegistrationMissingThenOAuth2AuthorizationException() {
		given(this.authorizationRequestRepository.removeAuthorizationRequest(any()))
				.willReturn(Mono.just(this.authorizationRequest.build()));
		given(this.clientRegistrationRepository.findByRegistrationId(any())).willReturn(Mono.empty());
		assertThatExceptionOfType(OAuth2AuthorizationException.class).isThrownBy(() -> applyConverter())
				.withMessageContaining(
						ServerOAuth2AuthorizationCodeAuthenticationTokenConverter.CLIENT_REGISTRATION_NOT_FOUND_ERROR_CODE);
	}

	@Test
	public void applyWhenCodeParameterNotFoundThenErrorCode() {
		this.request.queryParam(OAuth2ParameterNames.ERROR, "error");
		given(this.authorizationRequestRepository.removeAuthorizationRequest(any()))
				.willReturn(Mono.just(this.authorizationRequest.build()));
		given(this.clientRegistrationRepository.findByRegistrationId(any()))
				.willReturn(Mono.just(this.clientRegistration));
		assertThat(applyConverter().getAuthorizationExchange().getAuthorizationResponse().getError().getErrorCode())
				.isEqualTo("error");
	}

	@Test
	public void applyWhenCodeParameterFoundThenCode() {
		this.request.queryParam(OAuth2ParameterNames.CODE, "code");
		given(this.authorizationRequestRepository.removeAuthorizationRequest(any()))
				.willReturn(Mono.just(this.authorizationRequest.build()));
		given(this.clientRegistrationRepository.findByRegistrationId(any()))
				.willReturn(Mono.just(this.clientRegistration));
		OAuth2AuthorizationCodeAuthenticationToken result = applyConverter();
		OAuth2AuthorizationResponse exchange = result.getAuthorizationExchange().getAuthorizationResponse();
		assertThat(exchange.getError()).isNull();
		assertThat(exchange.getCode()).isEqualTo("code");
	}

	private OAuth2AuthorizationCodeAuthenticationToken applyConverter() {
		MockServerWebExchange exchange = MockServerWebExchange.from(this.request);
		return (OAuth2AuthorizationCodeAuthenticationToken) this.converter.convert(exchange).block();
	}

}
