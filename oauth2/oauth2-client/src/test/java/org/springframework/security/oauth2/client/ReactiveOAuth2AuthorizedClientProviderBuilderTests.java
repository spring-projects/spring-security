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

package org.springframework.security.oauth2.client;

import java.time.Duration;
import java.time.Instant;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import reactor.core.publisher.Mono;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.TestOAuth2RefreshTokens;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link ReactiveOAuth2AuthorizedClientProviderBuilder}.
 *
 * @author Joe Grandja
 */
public class ReactiveOAuth2AuthorizedClientProviderBuilderTests {

	private ClientRegistration.Builder clientRegistrationBuilder;

	private Authentication principal;

	private MockWebServer server;

	@Before
	public void setup() throws Exception {
		this.server = new MockWebServer();
		this.server.start();
		String tokenUri = this.server.url("/oauth2/token").toString();
		this.clientRegistrationBuilder = TestClientRegistrations.clientRegistration().tokenUri(tokenUri);
		this.principal = new TestingAuthenticationToken("principal", "password");
	}

	@After
	public void cleanup() throws Exception {
		this.server.shutdown();
	}

	@Test
	public void providerWhenNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> ReactiveOAuth2AuthorizedClientProviderBuilder.builder().provider(null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void buildWhenAuthorizationCodeProviderThenProviderAuthorizes() {
		ReactiveOAuth2AuthorizedClientProvider authorizedClientProvider = ReactiveOAuth2AuthorizedClientProviderBuilder
				.builder().authorizationCode().build();

		OAuth2AuthorizationContext authorizationContext = OAuth2AuthorizationContext
				.withClientRegistration(this.clientRegistrationBuilder.build()).principal(this.principal).build();
		assertThatThrownBy(() -> authorizedClientProvider.authorize(authorizationContext).block())
				.isInstanceOf(ClientAuthorizationRequiredException.class);
	}

	@Test
	public void buildWhenRefreshTokenProviderThenProviderReauthorizes() throws Exception {
		String accessTokenSuccessResponse = "{\n" + "	\"access_token\": \"access-token-1234\",\n"
				+ "   \"token_type\": \"bearer\",\n" + "   \"expires_in\": \"3600\"\n" + "}\n";
		this.server.enqueue(jsonResponse(accessTokenSuccessResponse));

		ReactiveOAuth2AuthorizedClientProvider authorizedClientProvider = ReactiveOAuth2AuthorizedClientProviderBuilder
				.builder().refreshToken().build();

		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.clientRegistrationBuilder.build(),
				this.principal.getName(), expiredAccessToken(), TestOAuth2RefreshTokens.refreshToken());

		OAuth2AuthorizationContext authorizationContext = OAuth2AuthorizationContext
				.withAuthorizedClient(authorizedClient).principal(this.principal).build();
		OAuth2AuthorizedClient reauthorizedClient = authorizedClientProvider.authorize(authorizationContext).block();

		assertThat(reauthorizedClient).isNotNull();

		assertThat(this.server.getRequestCount()).isEqualTo(1);

		RecordedRequest recordedRequest = this.server.takeRequest();
		String formParameters = recordedRequest.getBody().readUtf8();
		assertThat(formParameters).contains("grant_type=refresh_token");
	}

	@Test
	public void buildWhenClientCredentialsProviderThenProviderAuthorizes() throws Exception {
		String accessTokenSuccessResponse = "{\n" + "	\"access_token\": \"access-token-1234\",\n"
				+ "   \"token_type\": \"bearer\",\n" + "   \"expires_in\": \"3600\"\n" + "}\n";
		this.server.enqueue(jsonResponse(accessTokenSuccessResponse));

		ReactiveOAuth2AuthorizedClientProvider authorizedClientProvider = ReactiveOAuth2AuthorizedClientProviderBuilder
				.builder().clientCredentials().build();

		OAuth2AuthorizationContext authorizationContext = OAuth2AuthorizationContext
				.withClientRegistration(this.clientRegistrationBuilder
						.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).build())
				.principal(this.principal).build();
		OAuth2AuthorizedClient authorizedClient = authorizedClientProvider.authorize(authorizationContext).block();

		assertThat(authorizedClient).isNotNull();

		assertThat(this.server.getRequestCount()).isEqualTo(1);

		RecordedRequest recordedRequest = this.server.takeRequest();
		String formParameters = recordedRequest.getBody().readUtf8();
		assertThat(formParameters).contains("grant_type=client_credentials");
	}

	@Test
	public void buildWhenPasswordProviderThenProviderAuthorizes() throws Exception {
		String accessTokenSuccessResponse = "{\n" + "	\"access_token\": \"access-token-1234\",\n"
				+ "   \"token_type\": \"bearer\",\n" + "   \"expires_in\": \"3600\"\n" + "}\n";
		this.server.enqueue(jsonResponse(accessTokenSuccessResponse));

		ReactiveOAuth2AuthorizedClientProvider authorizedClientProvider = ReactiveOAuth2AuthorizedClientProviderBuilder
				.builder().password().build();

		OAuth2AuthorizationContext authorizationContext = OAuth2AuthorizationContext
				.withClientRegistration(
						this.clientRegistrationBuilder.authorizationGrantType(AuthorizationGrantType.PASSWORD).build())
				.principal(this.principal).attribute(OAuth2AuthorizationContext.USERNAME_ATTRIBUTE_NAME, "username")
				.attribute(OAuth2AuthorizationContext.PASSWORD_ATTRIBUTE_NAME, "password").build();
		OAuth2AuthorizedClient authorizedClient = authorizedClientProvider.authorize(authorizationContext).block();

		assertThat(authorizedClient).isNotNull();

		assertThat(this.server.getRequestCount()).isEqualTo(1);

		RecordedRequest recordedRequest = this.server.takeRequest();
		String formParameters = recordedRequest.getBody().readUtf8();
		assertThat(formParameters).contains("grant_type=password");
	}

	@Test
	public void buildWhenAllProvidersThenProvidersAuthorize() throws Exception {
		String accessTokenSuccessResponse = "{\n" + "	\"access_token\": \"access-token-1234\",\n"
				+ "   \"token_type\": \"bearer\",\n" + "   \"expires_in\": \"3600\"\n" + "}\n";
		this.server.enqueue(jsonResponse(accessTokenSuccessResponse));
		this.server.enqueue(jsonResponse(accessTokenSuccessResponse));
		this.server.enqueue(jsonResponse(accessTokenSuccessResponse));

		ReactiveOAuth2AuthorizedClientProvider authorizedClientProvider = ReactiveOAuth2AuthorizedClientProviderBuilder
				.builder().authorizationCode().refreshToken().clientCredentials().password().build();

		// authorization_code
		OAuth2AuthorizationContext authorizationCodeContext = OAuth2AuthorizationContext
				.withClientRegistration(this.clientRegistrationBuilder.build()).principal(this.principal).build();
		assertThatThrownBy(() -> authorizedClientProvider.authorize(authorizationCodeContext).block())
				.isInstanceOf(ClientAuthorizationRequiredException.class);

		// refresh_token
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.clientRegistrationBuilder.build(),
				this.principal.getName(), expiredAccessToken(), TestOAuth2RefreshTokens.refreshToken());

		OAuth2AuthorizationContext refreshTokenContext = OAuth2AuthorizationContext
				.withAuthorizedClient(authorizedClient).principal(this.principal).build();
		OAuth2AuthorizedClient reauthorizedClient = authorizedClientProvider.authorize(refreshTokenContext).block();

		assertThat(reauthorizedClient).isNotNull();

		assertThat(this.server.getRequestCount()).isEqualTo(1);

		RecordedRequest recordedRequest = this.server.takeRequest();
		String formParameters = recordedRequest.getBody().readUtf8();
		assertThat(formParameters).contains("grant_type=refresh_token");

		// client_credentials
		OAuth2AuthorizationContext clientCredentialsContext = OAuth2AuthorizationContext
				.withClientRegistration(this.clientRegistrationBuilder
						.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).build())
				.principal(this.principal).build();
		authorizedClient = authorizedClientProvider.authorize(clientCredentialsContext).block();

		assertThat(authorizedClient).isNotNull();

		assertThat(this.server.getRequestCount()).isEqualTo(2);

		recordedRequest = this.server.takeRequest();
		formParameters = recordedRequest.getBody().readUtf8();
		assertThat(formParameters).contains("grant_type=client_credentials");

		// password
		OAuth2AuthorizationContext passwordContext = OAuth2AuthorizationContext
				.withClientRegistration(
						this.clientRegistrationBuilder.authorizationGrantType(AuthorizationGrantType.PASSWORD).build())
				.principal(this.principal).attribute(OAuth2AuthorizationContext.USERNAME_ATTRIBUTE_NAME, "username")
				.attribute(OAuth2AuthorizationContext.PASSWORD_ATTRIBUTE_NAME, "password").build();
		authorizedClient = authorizedClientProvider.authorize(passwordContext).block();

		assertThat(authorizedClient).isNotNull();

		assertThat(this.server.getRequestCount()).isEqualTo(3);

		recordedRequest = this.server.takeRequest();
		formParameters = recordedRequest.getBody().readUtf8();
		assertThat(formParameters).contains("grant_type=password");
	}

	@Test
	public void buildWhenCustomProviderThenProviderCalled() {
		ReactiveOAuth2AuthorizedClientProvider customProvider = mock(ReactiveOAuth2AuthorizedClientProvider.class);
		given(customProvider.authorize(any())).willReturn(Mono.empty());

		ReactiveOAuth2AuthorizedClientProvider authorizedClientProvider = ReactiveOAuth2AuthorizedClientProviderBuilder
				.builder().provider(customProvider).build();

		OAuth2AuthorizationContext authorizationContext = OAuth2AuthorizationContext
				.withClientRegistration(this.clientRegistrationBuilder.build()).principal(this.principal).build();
		authorizedClientProvider.authorize(authorizationContext).block();

		verify(customProvider).authorize(any(OAuth2AuthorizationContext.class));
	}

	private OAuth2AccessToken expiredAccessToken() {
		Instant issuedAt = Instant.now().minus(Duration.ofDays(1));
		Instant expiresAt = issuedAt.plus(Duration.ofMinutes(60));
		return new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "access-token-1234", issuedAt, expiresAt);
	}

	private MockResponse jsonResponse(String json) {
		return new MockResponse().setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE).setBody(json);
	}

}
