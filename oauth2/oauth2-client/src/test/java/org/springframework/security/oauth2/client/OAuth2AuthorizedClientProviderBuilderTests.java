/*
 * Copyright 2002-2024 the original author or authors.
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
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.endpoint.DefaultPasswordTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.RestClientClientCredentialsTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.RestClientRefreshTokenTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.TestOAuth2RefreshTokens;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.test.web.client.ExpectedCount;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.client.ExpectedCount.once;
import static org.springframework.test.web.client.ExpectedCount.times;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

/**
 * Tests for {@link OAuth2AuthorizedClientProviderBuilder}.
 *
 * @author Joe Grandja
 */
public class OAuth2AuthorizedClientProviderBuilderTests {

	private RestClientClientCredentialsTokenResponseClient clientCredentialsTokenResponseClient;

	private RestClientRefreshTokenTokenResponseClient refreshTokenTokenResponseClient;

	private DefaultPasswordTokenResponseClient passwordTokenResponseClient;

	private Authentication principal;

	private MockRestServiceServer server;

	@BeforeEach
	public void setup() {
		// TODO: Use of RestTemplate in these tests can be removed when
		// DefaultPasswordTokenResponseClient is removed.
		RestTemplate accessTokenClient = new RestTemplate(
				List.of(new FormHttpMessageConverter(), new OAuth2AccessTokenResponseHttpMessageConverter()));
		this.server = MockRestServiceServer.bindTo(accessTokenClient).build();
		RestClient restClient = RestClient.create(accessTokenClient);
		this.refreshTokenTokenResponseClient = new RestClientRefreshTokenTokenResponseClient();
		this.refreshTokenTokenResponseClient.setRestClient(restClient);
		this.clientCredentialsTokenResponseClient = new RestClientClientCredentialsTokenResponseClient();
		this.clientCredentialsTokenResponseClient.setRestClient(restClient);
		this.passwordTokenResponseClient = new DefaultPasswordTokenResponseClient();
		this.passwordTokenResponseClient.setRestOperations(accessTokenClient);
		this.principal = new TestingAuthenticationToken("principal", "password");
	}

	@Test
	public void providerWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> OAuth2AuthorizedClientProviderBuilder.builder().provider(null));
	}

	@Test
	public void buildWhenAuthorizationCodeProviderThenProviderAuthorizes() {
		// @formatter:off
		OAuth2AuthorizedClientProvider authorizedClientProvider = OAuth2AuthorizedClientProviderBuilder.builder()
				.authorizationCode()
				.build();
		OAuth2AuthorizationContext authorizationContext = OAuth2AuthorizationContext
				.withClientRegistration(TestClientRegistrations.clientRegistration().build())
				.principal(this.principal)
				.build();
		// @formatter:on
		assertThatExceptionOfType(ClientAuthorizationRequiredException.class)
			.isThrownBy(() -> authorizedClientProvider.authorize(authorizationContext));
	}

	@Test
	public void buildWhenRefreshTokenProviderThenProviderReauthorizes() {
		mockAccessTokenResponse(once());

		OAuth2AuthorizedClientProvider authorizedClientProvider = OAuth2AuthorizedClientProviderBuilder.builder()
			.refreshToken((configurer) -> configurer.accessTokenResponseClient(this.refreshTokenTokenResponseClient))
			.build();
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(
				TestClientRegistrations.clientRegistration().build(), this.principal.getName(), expiredAccessToken(),
				TestOAuth2RefreshTokens.refreshToken());
		// @formatter:off
		OAuth2AuthorizationContext authorizationContext = OAuth2AuthorizationContext
				.withAuthorizedClient(authorizedClient)
				.principal(this.principal)
				.build();
		// @formatter:on
		OAuth2AuthorizedClient reauthorizedClient = authorizedClientProvider.authorize(authorizationContext);
		assertThat(reauthorizedClient).isNotNull();
		this.server.verify();
	}

	@Test
	public void buildWhenClientCredentialsProviderThenProviderAuthorizes() {
		mockAccessTokenResponse(once());

		OAuth2AuthorizedClientProvider authorizedClientProvider = OAuth2AuthorizedClientProviderBuilder.builder()
			.clientCredentials(
					(configurer) -> configurer.accessTokenResponseClient(this.clientCredentialsTokenResponseClient))
			.build();
		// @formatter:off
		OAuth2AuthorizationContext authorizationContext = OAuth2AuthorizationContext
				.withClientRegistration(TestClientRegistrations.clientCredentials().build())
				.principal(this.principal)
				.build();
		// @formatter:on
		OAuth2AuthorizedClient authorizedClient = authorizedClientProvider.authorize(authorizationContext);
		assertThat(authorizedClient).isNotNull();
		this.server.verify();
	}

	@Test
	public void buildWhenPasswordProviderThenProviderAuthorizes() {
		mockAccessTokenResponse(once());

		// @formatter:off
		OAuth2AuthorizedClientProvider authorizedClientProvider = OAuth2AuthorizedClientProviderBuilder.builder()
				.password((configurer) -> configurer.accessTokenResponseClient(this.passwordTokenResponseClient))
				.build();
		OAuth2AuthorizationContext authorizationContext = OAuth2AuthorizationContext
				.withClientRegistration(TestClientRegistrations.password().build())
				.principal(this.principal)
				.attribute(OAuth2AuthorizationContext.USERNAME_ATTRIBUTE_NAME, "username")
				.attribute(OAuth2AuthorizationContext.PASSWORD_ATTRIBUTE_NAME, "password")
				.build();
		// @formatter:on
		OAuth2AuthorizedClient authorizedClient = authorizedClientProvider.authorize(authorizationContext);
		assertThat(authorizedClient).isNotNull();
		this.server.verify();
	}

	@Test
	public void buildWhenAllProvidersThenProvidersAuthorize() {
		mockAccessTokenResponse(times(3));

		OAuth2AuthorizedClientProvider authorizedClientProvider = OAuth2AuthorizedClientProviderBuilder.builder()
			.authorizationCode()
			.refreshToken((configurer) -> configurer.accessTokenResponseClient(this.refreshTokenTokenResponseClient))
			.clientCredentials(
					(configurer) -> configurer.accessTokenResponseClient(this.clientCredentialsTokenResponseClient))
			.password((configurer) -> configurer.accessTokenResponseClient(this.passwordTokenResponseClient))
			.build();
		ClientRegistration clientRegistration = TestClientRegistrations.clientRegistration().build();
		// authorization_code
		// @formatter:off
		OAuth2AuthorizationContext authorizationCodeContext = OAuth2AuthorizationContext
				.withClientRegistration(clientRegistration)
				.principal(this.principal)
				.build();
		// @formatter:on
		assertThatExceptionOfType(ClientAuthorizationRequiredException.class)
			.isThrownBy(() -> authorizedClientProvider.authorize(authorizationCodeContext));
		// refresh_token
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(clientRegistration,
				this.principal.getName(), expiredAccessToken(), TestOAuth2RefreshTokens.refreshToken());
		OAuth2AuthorizationContext refreshTokenContext = OAuth2AuthorizationContext
			.withAuthorizedClient(authorizedClient)
			.principal(this.principal)
			.build();
		OAuth2AuthorizedClient reauthorizedClient = authorizedClientProvider.authorize(refreshTokenContext);
		assertThat(reauthorizedClient).isNotNull();
		// client_credentials
		// @formatter:off
		OAuth2AuthorizationContext clientCredentialsContext = OAuth2AuthorizationContext
				.withClientRegistration(TestClientRegistrations.clientCredentials().build())
				.principal(this.principal)
				.build();
		// @formatter:on
		authorizedClient = authorizedClientProvider.authorize(clientCredentialsContext);
		assertThat(authorizedClient).isNotNull();
		// password
		// @formatter:off
		OAuth2AuthorizationContext passwordContext = OAuth2AuthorizationContext
				.withClientRegistration(TestClientRegistrations.password().build())
				.principal(this.principal)
				.attribute(OAuth2AuthorizationContext.USERNAME_ATTRIBUTE_NAME, "username")
				.attribute(OAuth2AuthorizationContext.PASSWORD_ATTRIBUTE_NAME, "password")
				.build();
		// @formatter:on
		authorizedClient = authorizedClientProvider.authorize(passwordContext);
		assertThat(authorizedClient).isNotNull();
		this.server.verify();
	}

	@Test
	public void buildWhenCustomProviderThenProviderCalled() {
		OAuth2AuthorizedClientProvider customProvider = mock(OAuth2AuthorizedClientProvider.class);
		// @formatter:off
		OAuth2AuthorizedClientProvider authorizedClientProvider = OAuth2AuthorizedClientProviderBuilder.builder()
				.provider(customProvider)
				.build();
		OAuth2AuthorizationContext authorizationContext = OAuth2AuthorizationContext
				.withClientRegistration(TestClientRegistrations.clientRegistration().build())
				.principal(this.principal)
				.build();
		// @formatter:on
		authorizedClientProvider.authorize(authorizationContext);
		verify(customProvider).authorize(any(OAuth2AuthorizationContext.class));
	}

	private OAuth2AccessToken expiredAccessToken() {
		Instant issuedAt = Instant.now().minus(Duration.ofDays(1));
		Instant expiresAt = issuedAt.plus(Duration.ofMinutes(60));
		return new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "access-token-1234", issuedAt, expiresAt);
	}

	private void mockAccessTokenResponse(ExpectedCount expectedCount) {
		this.server.expect(expectedCount, requestTo("https://example.com/login/oauth/access_token"))
			.andRespond(withSuccess().header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
				.body(new ClassPathResource("access-token-response.json")));
	}

}
