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
package org.springframework.security.oauth2.client.web.reactive.function.client;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.core.codec.ByteBufferEncoder;
import org.springframework.core.codec.CharSequenceEncoder;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.http.codec.EncoderHttpMessageWriter;
import org.springframework.http.codec.FormHttpMessageWriter;
import org.springframework.http.codec.HttpMessageWriter;
import org.springframework.http.codec.ResourceHttpMessageWriter;
import org.springframework.http.codec.ServerSentEventHttpMessageWriter;
import org.springframework.http.codec.json.Jackson2JsonEncoder;
import org.springframework.http.codec.multipart.MultipartHttpMessageWriter;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.mock.http.client.reactive.MockClientHttpRequest;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.RefreshTokenOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.endpoint.DefaultClientCredentialsTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.DefaultRefreshTokenTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2ClientCredentialsGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2PasswordGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.TestOAuth2AccessTokenResponses;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestOperations;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.reactive.function.BodyInserter;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.CoreSubscriber;
import reactor.core.publisher.BaseSubscriber;
import reactor.core.publisher.Mono;
import reactor.util.context.Context;

import javax.servlet.http.HttpServletRequest;
import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.mockito.Mockito.*;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.security.oauth2.client.web.reactive.function.client.ServerOAuth2AuthorizedClientExchangeFilterFunction.clientRegistrationId;
import static org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction.*;

/**
 * @author Rob Winch
 * @since 5.1
 */
@RunWith(MockitoJUnitRunner.class)
public class ServletOAuth2AuthorizedClientExchangeFilterFunctionTests {
	@Mock
	private OAuth2AuthorizedClientRepository authorizedClientRepository;
	@Mock
	private ClientRegistrationRepository clientRegistrationRepository;
	@Mock
	private OAuth2AccessTokenResponseClient<OAuth2ClientCredentialsGrantRequest> clientCredentialsTokenResponseClient;
	@Mock
	private OAuth2AccessTokenResponseClient<OAuth2RefreshTokenGrantRequest> refreshTokenTokenResponseClient;
	@Mock
	private OAuth2AccessTokenResponseClient<OAuth2PasswordGrantRequest> passwordTokenResponseClient;
	@Mock
	private WebClient.RequestHeadersSpec<?> spec;
	@Captor
	private ArgumentCaptor<Consumer<Map<String, Object>>> attrs;
	@Captor
	private ArgumentCaptor<OAuth2AuthorizedClient> authorizedClientCaptor;

	private DefaultOAuth2AuthorizedClientManager authorizedClientManager;

	/**
	 * Used for get the attributes from defaultRequest.
	 */
	private Map<String, Object> result = new HashMap<>();

	private ServletOAuth2AuthorizedClientExchangeFilterFunction function;

	private MockExchangeFunction exchange = new MockExchangeFunction();

	private Authentication authentication;

	private ClientRegistration registration = TestClientRegistrations.clientRegistration().build();

	private OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
			"token-0",
			Instant.now(),
			Instant.now().plus(Duration.ofDays(1)));

	@Before
	public void setup() {
		this.authentication = new TestingAuthenticationToken("test", "this");
		OAuth2AuthorizedClientProvider authorizedClientProvider =
				OAuth2AuthorizedClientProviderBuilder.builder()
						.authorizationCode()
						.refreshToken(configurer -> configurer.accessTokenResponseClient(this.refreshTokenTokenResponseClient))
						.clientCredentials(configurer -> configurer.accessTokenResponseClient(this.clientCredentialsTokenResponseClient))
						.password(configurer -> configurer.accessTokenResponseClient(this.passwordTokenResponseClient))
						.build();
		this.authorizedClientManager = new DefaultOAuth2AuthorizedClientManager(
				this.clientRegistrationRepository, this.authorizedClientRepository);
		this.authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);
		this.function = new ServletOAuth2AuthorizedClientExchangeFilterFunction(authorizedClientManager);
	}

	@After
	public void cleanup() throws Exception {
		SecurityContextHolder.clearContext();
		RequestContextHolder.resetRequestAttributes();
		this.function.destroy();
	}

	@Test
	public void constructorWhenAuthorizedClientManagerIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new ServletOAuth2AuthorizedClientExchangeFilterFunction(null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void setClientCredentialsTokenResponseClientWhenClientIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.function.setClientCredentialsTokenResponseClient(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("clientCredentialsTokenResponseClient cannot be null");
	}

	@Test
	public void setClientCredentialsTokenResponseClientWhenNotDefaultAuthorizedClientManagerThenThrowIllegalStateException() {
		assertThatThrownBy(() -> this.function.setClientCredentialsTokenResponseClient(new DefaultClientCredentialsTokenResponseClient()))
				.isInstanceOf(IllegalStateException.class)
				.hasMessage("The client cannot be set when the constructor used is \"ServletOAuth2AuthorizedClientExchangeFilterFunction(OAuth2AuthorizedClientManager)\". " +
						"Instead, use the constructor \"ServletOAuth2AuthorizedClientExchangeFilterFunction(ClientRegistrationRepository, OAuth2AuthorizedClientRepository)\".");
	}

	@Test
	public void setAccessTokenExpiresSkewWhenNotDefaultAuthorizedClientManagerThenThrowIllegalStateException() {
		assertThatThrownBy(() -> this.function.setAccessTokenExpiresSkew(Duration.ofSeconds(30)))
				.isInstanceOf(IllegalStateException.class)
				.hasMessage("The accessTokenExpiresSkew cannot be set when the constructor used is \"ServletOAuth2AuthorizedClientExchangeFilterFunction(OAuth2AuthorizedClientManager)\". " +
						"Instead, use the constructor \"ServletOAuth2AuthorizedClientExchangeFilterFunction(ClientRegistrationRepository, OAuth2AuthorizedClientRepository)\".");
	}

	@Test
	public void defaultRequestRequestResponseWhenNullRequestContextThenRequestAndResponseNull() {
		Map<String, Object> attrs = getDefaultRequestAttributes();
		assertThat(getRequest(attrs)).isNull();
		assertThat(getResponse(attrs)).isNull();
	}

	@Test
	public void defaultRequestRequestResponseWhenRequestContextThenRequestAndResponseSet() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));
		Map<String, Object> attrs = getDefaultRequestAttributes();
		assertThat(getRequest(attrs)).isEqualTo(request);
		assertThat(getResponse(attrs)).isEqualTo(response);
	}

	@Test
	public void defaultRequestAuthenticationWhenSecurityContextEmptyThenAuthenticationNull() {
		Map<String, Object> attrs = getDefaultRequestAttributes();
		assertThat(getAuthentication(attrs)).isNull();
	}

	@Test
	public void defaultRequestAuthenticationWhenAuthenticationSetThenAuthenticationSet() {
		SecurityContextHolder.getContext().setAuthentication(this.authentication);
		Map<String, Object> attrs = getDefaultRequestAttributes();
		assertThat(getAuthentication(attrs)).isEqualTo(this.authentication);
		verifyZeroInteractions(this.authorizedClientRepository);
	}

	private Map<String, Object> getDefaultRequestAttributes() {
		this.function.defaultRequest().accept(this.spec);
		verify(this.spec).attributes(this.attrs.capture());

		this.attrs.getValue().accept(this.result);

		return this.result;
	}

	@Test
	public void filterWhenAuthorizedClientNullThenAuthorizationHeaderNull() {
		ClientRequest request = ClientRequest.create(GET, URI.create("https://example.com"))
				.build();

		this.function.filter(request, this.exchange).block();

		assertThat(this.exchange.getRequest().headers().getFirst(HttpHeaders.AUTHORIZATION)).isNull();
	}

	@Test
	public void filterWhenAuthorizedClientThenAuthorizationHeader() {
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration,
				"principalName", this.accessToken);

		ClientRequest request = ClientRequest.create(GET, URI.create("https://example.com"))
				.attributes(oauth2AuthorizedClient(authorizedClient))
				.attributes(httpServletRequest(new MockHttpServletRequest()))
				.attributes(httpServletResponse(new MockHttpServletResponse()))
				.build();

		this.function.filter(request, this.exchange).block();

		assertThat(this.exchange.getRequest().headers().getFirst(HttpHeaders.AUTHORIZATION)).isEqualTo("Bearer " + this.accessToken.getTokenValue());
	}

	@Test
	public void filterWhenExistingAuthorizationThenSingleAuthorizationHeader() {
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration,
				"principalName", this.accessToken);

		ClientRequest request = ClientRequest.create(GET, URI.create("https://example.com"))
				.header(HttpHeaders.AUTHORIZATION, "Existing")
				.attributes(oauth2AuthorizedClient(authorizedClient))
				.attributes(httpServletRequest(new MockHttpServletRequest()))
				.attributes(httpServletResponse(new MockHttpServletResponse()))
				.build();

		this.function.filter(request, this.exchange).block();

		HttpHeaders headers = this.exchange.getRequest().headers();
		assertThat(headers.get(HttpHeaders.AUTHORIZATION)).containsOnly("Bearer " + this.accessToken.getTokenValue());
	}

	@Test
	public void filterWhenRefreshRequiredThenRefresh() {
		OAuth2AccessTokenResponse response = OAuth2AccessTokenResponse.withToken("token-1")
				.tokenType(OAuth2AccessToken.TokenType.BEARER)
				.expiresIn(3600)
				.refreshToken("refresh-1")
				.build();
		when(this.refreshTokenTokenResponseClient.getTokenResponse(any())).thenReturn(response);

		Instant issuedAt = Instant.now().minus(Duration.ofDays(1));
		Instant accessTokenExpiresAt = issuedAt.plus(Duration.ofHours(1));
		this.accessToken = new OAuth2AccessToken(this.accessToken.getTokenType(),
				this.accessToken.getTokenValue(),
				issuedAt,
				accessTokenExpiresAt);
		OAuth2RefreshToken refreshToken = new OAuth2RefreshToken("refresh-token", issuedAt);
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration,
				"principalName", this.accessToken, refreshToken);

		ClientRequest request = ClientRequest.create(GET, URI.create("https://example.com"))
				.attributes(oauth2AuthorizedClient(authorizedClient))
				.attributes(authentication(this.authentication))
				.attributes(httpServletRequest(new MockHttpServletRequest()))
				.attributes(httpServletResponse(new MockHttpServletResponse()))
				.build();

		this.function.filter(request, this.exchange).block();

		verify(this.refreshTokenTokenResponseClient).getTokenResponse(any());
		verify(this.authorizedClientRepository).saveAuthorizedClient(
				this.authorizedClientCaptor.capture(), eq(this.authentication), any(), any());

		OAuth2AuthorizedClient newAuthorizedClient = authorizedClientCaptor.getValue();
		assertThat(newAuthorizedClient.getAccessToken()).isEqualTo(response.getAccessToken());
		assertThat(newAuthorizedClient.getRefreshToken()).isEqualTo(response.getRefreshToken());

		List<ClientRequest> requests = this.exchange.getRequests();
		assertThat(requests).hasSize(1);

		ClientRequest request0 = requests.get(0);
		assertThat(request0.headers().getFirst(HttpHeaders.AUTHORIZATION)).isEqualTo("Bearer token-1");
		assertThat(request0.url().toASCIIString()).isEqualTo("https://example.com");
		assertThat(request0.method()).isEqualTo(HttpMethod.GET);
		assertThat(getBody(request0)).isEmpty();
	}

	@Test
	public void filterWhenRefreshRequiredThenRefreshAndResponseDoesNotContainRefreshToken() {
		OAuth2AccessTokenResponse response = OAuth2AccessTokenResponse.withToken("token-1")
				.tokenType(OAuth2AccessToken.TokenType.BEARER)
				.expiresIn(3600)
//				.refreshToken(xxx)  // No refreshToken in response
				.build();

		RestOperations refreshTokenClient = mock(RestOperations.class);
		when(refreshTokenClient.exchange(any(RequestEntity.class), eq(OAuth2AccessTokenResponse.class)))
				.thenReturn(new ResponseEntity(response, HttpStatus.OK));
		DefaultRefreshTokenTokenResponseClient refreshTokenTokenResponseClient = new DefaultRefreshTokenTokenResponseClient();
		refreshTokenTokenResponseClient.setRestOperations(refreshTokenClient);

		RefreshTokenOAuth2AuthorizedClientProvider authorizedClientProvider = new RefreshTokenOAuth2AuthorizedClientProvider();
		authorizedClientProvider.setAccessTokenResponseClient(refreshTokenTokenResponseClient);
		DefaultOAuth2AuthorizedClientManager authorizedClientManager = new DefaultOAuth2AuthorizedClientManager(
				this.clientRegistrationRepository, this.authorizedClientRepository);
		authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);
		this.function = new ServletOAuth2AuthorizedClientExchangeFilterFunction(authorizedClientManager);

		Instant issuedAt = Instant.now().minus(Duration.ofDays(1));
		Instant accessTokenExpiresAt = issuedAt.plus(Duration.ofHours(1));
		this.accessToken = new OAuth2AccessToken(this.accessToken.getTokenType(),
				this.accessToken.getTokenValue(),
				issuedAt,
				accessTokenExpiresAt);
		OAuth2RefreshToken refreshToken = new OAuth2RefreshToken("refresh-token", issuedAt);
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration,
				"principalName", this.accessToken, refreshToken);

		ClientRequest request = ClientRequest.create(GET, URI.create("https://example.com"))
				.attributes(oauth2AuthorizedClient(authorizedClient))
				.attributes(authentication(this.authentication))
				.attributes(httpServletRequest(new MockHttpServletRequest()))
				.attributes(httpServletResponse(new MockHttpServletResponse()))
				.build();

		this.function.filter(request, this.exchange).block();

		verify(refreshTokenClient).exchange(any(RequestEntity.class), eq(OAuth2AccessTokenResponse.class));
		verify(this.authorizedClientRepository).saveAuthorizedClient(this.authorizedClientCaptor.capture(), eq(this.authentication), any(), any());

		OAuth2AuthorizedClient newAuthorizedClient = authorizedClientCaptor.getValue();
		assertThat(newAuthorizedClient.getAccessToken()).isEqualTo(response.getAccessToken());
		assertThat(newAuthorizedClient.getRefreshToken().getTokenValue()).isEqualTo(refreshToken.getTokenValue());

		List<ClientRequest> requests = this.exchange.getRequests();
		assertThat(requests).hasSize(1);

		ClientRequest request0 = requests.get(0);
		assertThat(request0.headers().getFirst(HttpHeaders.AUTHORIZATION)).isEqualTo("Bearer token-1");
		assertThat(request0.url().toASCIIString()).isEqualTo("https://example.com");
		assertThat(request0.method()).isEqualTo(HttpMethod.GET);
		assertThat(getBody(request0)).isEmpty();
	}

	@Test
	public void filterWhenClientCredentialsTokenNotExpiredThenUseCurrentToken() {
		this.registration = TestClientRegistrations.clientCredentials().build();
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration,
				"principalName", this.accessToken, null);

		ClientRequest request = ClientRequest.create(GET, URI.create("https://example.com"))
				.attributes(oauth2AuthorizedClient(authorizedClient))
				.attributes(authentication(this.authentication))
				.attributes(httpServletRequest(new MockHttpServletRequest()))
				.attributes(httpServletResponse(new MockHttpServletResponse()))
				.build();

		this.function.filter(request, this.exchange).block();

		verify(this.authorizedClientRepository, never()).saveAuthorizedClient(any(), eq(this.authentication), any(), any());

		verify(clientCredentialsTokenResponseClient, never()).getTokenResponse(any());

		List<ClientRequest> requests = this.exchange.getRequests();
		assertThat(requests).hasSize(1);

		ClientRequest request1 = requests.get(0);
		assertThat(request1.headers().getFirst(HttpHeaders.AUTHORIZATION)).isEqualTo("Bearer token-0");
		assertThat(request1.url().toASCIIString()).isEqualTo("https://example.com");
		assertThat(request1.method()).isEqualTo(HttpMethod.GET);
		assertThat(getBody(request1)).isEmpty();
	}

	@Test
	public void filterWhenClientCredentialsTokenExpiredThenGetNewToken() {
		this.registration = TestClientRegistrations.clientCredentials().build();

		OAuth2AccessTokenResponse accessTokenResponse = TestOAuth2AccessTokenResponses
				.accessTokenResponse().build();
		when(this.clientCredentialsTokenResponseClient.getTokenResponse(any())).thenReturn(
				accessTokenResponse);

		Instant issuedAt = Instant.now().minus(Duration.ofDays(1));
		Instant accessTokenExpiresAt = issuedAt.plus(Duration.ofHours(1));
		this.accessToken = new OAuth2AccessToken(this.accessToken.getTokenType(),
				this.accessToken.getTokenValue(),
				issuedAt,
				accessTokenExpiresAt);

		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration,
				"principalName", this.accessToken, null);

		ClientRequest request = ClientRequest.create(GET, URI.create("https://example.com"))
				.attributes(oauth2AuthorizedClient(authorizedClient))
				.attributes(authentication(this.authentication))
				.attributes(httpServletRequest(new MockHttpServletRequest()))
				.attributes(httpServletResponse(new MockHttpServletResponse()))
				.build();

		this.function.filter(request, this.exchange).block();

		verify(this.authorizedClientRepository).saveAuthorizedClient(any(), eq(this.authentication), any(), any());

		verify(this.clientCredentialsTokenResponseClient).getTokenResponse(any());

		List<ClientRequest> requests = this.exchange.getRequests();
		assertThat(requests).hasSize(1);

		ClientRequest request1 = requests.get(0);
		assertThat(request1.headers().getFirst(HttpHeaders.AUTHORIZATION)).isEqualTo("Bearer token");
		assertThat(request1.url().toASCIIString()).isEqualTo("https://example.com");
		assertThat(request1.method()).isEqualTo(HttpMethod.GET);
		assertThat(getBody(request1)).isEmpty();
	}

	@Test
	public void filterWhenPasswordClientNotAuthorizedThenGetNewToken() {
		OAuth2AccessTokenResponse accessTokenResponse = OAuth2AccessTokenResponse.withToken("new-token")
				.tokenType(OAuth2AccessToken.TokenType.BEARER)
				.expiresIn(360)
				.build();
		when(this.passwordTokenResponseClient.getTokenResponse(any())).thenReturn(accessTokenResponse);

		ClientRegistration registration = TestClientRegistrations.password().build();
		when(this.clientRegistrationRepository.findByRegistrationId(eq(registration.getRegistrationId()))).thenReturn(registration);

		// Set custom contextAttributesMapper
		this.authorizedClientManager.setContextAttributesMapper(authorizeRequest -> {
			Map<String, Object> contextAttributes = new HashMap<>();
			HttpServletRequest servletRequest = authorizeRequest.getAttribute(HttpServletRequest.class.getName());
			String username = servletRequest.getParameter(OAuth2ParameterNames.USERNAME);
			String password = servletRequest.getParameter(OAuth2ParameterNames.PASSWORD);
			if (StringUtils.hasText(username) && StringUtils.hasText(password)) {
				contextAttributes.put(OAuth2AuthorizationContext.USERNAME_ATTRIBUTE_NAME, username);
				contextAttributes.put(OAuth2AuthorizationContext.PASSWORD_ATTRIBUTE_NAME, password);
			}
			return contextAttributes;
		});

		MockHttpServletRequest servletRequest = new MockHttpServletRequest();
		servletRequest.setParameter(OAuth2ParameterNames.USERNAME, "username");
		servletRequest.setParameter(OAuth2ParameterNames.PASSWORD, "password");
		MockHttpServletResponse servletResponse = new MockHttpServletResponse();

		ClientRequest request = ClientRequest.create(GET, URI.create("https://example.com"))
				.attributes(clientRegistrationId(registration.getRegistrationId()))
				.attributes(authentication(this.authentication))
				.attributes(httpServletRequest(servletRequest))
				.attributes(httpServletResponse(servletResponse))
				.build();

		this.function.filter(request, this.exchange).block();

		verify(this.passwordTokenResponseClient).getTokenResponse(any());
		verify(this.authorizedClientRepository).saveAuthorizedClient(any(), eq(authentication), any(), any());

		List<ClientRequest> requests = this.exchange.getRequests();
		assertThat(requests).hasSize(1);
		ClientRequest request1 = requests.get(0);
		assertThat(request1.headers().getFirst(HttpHeaders.AUTHORIZATION)).isEqualTo("Bearer new-token");
		assertThat(request1.url().toASCIIString()).isEqualTo("https://example.com");
		assertThat(request1.method()).isEqualTo(HttpMethod.GET);
		assertThat(getBody(request1)).isEmpty();
	}

	@Test
	public void filterWhenRefreshRequiredAndEmptyReactiveSecurityContextThenSaved() {
		OAuth2AccessTokenResponse response = OAuth2AccessTokenResponse.withToken("token-1")
				.tokenType(OAuth2AccessToken.TokenType.BEARER)
				.expiresIn(3600)
				.refreshToken("refresh-1")
				.build();
		when(this.refreshTokenTokenResponseClient.getTokenResponse(any())).thenReturn(response);

		Instant issuedAt = Instant.now().minus(Duration.ofDays(1));
		Instant accessTokenExpiresAt = issuedAt.plus(Duration.ofHours(1));
		this.accessToken = new OAuth2AccessToken(this.accessToken.getTokenType(),
				this.accessToken.getTokenValue(), issuedAt, accessTokenExpiresAt);
		OAuth2RefreshToken refreshToken = new OAuth2RefreshToken("refresh-token", issuedAt);
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration,
				"principalName", this.accessToken, refreshToken);

		ClientRequest request = ClientRequest.create(GET, URI.create("https://example.com"))
				.attributes(oauth2AuthorizedClient(authorizedClient))
				.attributes(httpServletRequest(new MockHttpServletRequest()))
				.attributes(httpServletResponse(new MockHttpServletResponse()))
				.build();

		this.function.filter(request, this.exchange).block();

		verify(this.refreshTokenTokenResponseClient).getTokenResponse(any());
		verify(this.authorizedClientRepository).saveAuthorizedClient(any(), any(), any(), any());

		List<ClientRequest> requests = this.exchange.getRequests();
		assertThat(requests).hasSize(1);

		ClientRequest request0 = requests.get(0);
		assertThat(request0.headers().getFirst(HttpHeaders.AUTHORIZATION)).isEqualTo("Bearer token-1");
		assertThat(request0.url().toASCIIString()).isEqualTo("https://example.com");
		assertThat(request0.method()).isEqualTo(HttpMethod.GET);
		assertThat(getBody(request0)).isEmpty();
	}

	@Test
	public void filterWhenRefreshTokenNullThenShouldRefreshFalse() {
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration,
				"principalName", this.accessToken);

		ClientRequest request = ClientRequest.create(GET, URI.create("https://example.com"))
				.attributes(oauth2AuthorizedClient(authorizedClient))
				.attributes(httpServletRequest(new MockHttpServletRequest()))
				.attributes(httpServletResponse(new MockHttpServletResponse()))
				.build();

		this.function.filter(request, this.exchange).block();

		List<ClientRequest> requests = this.exchange.getRequests();
		assertThat(requests).hasSize(1);

		ClientRequest request0 = requests.get(0);
		assertThat(request0.headers().getFirst(HttpHeaders.AUTHORIZATION)).isEqualTo("Bearer token-0");
		assertThat(request0.url().toASCIIString()).isEqualTo("https://example.com");
		assertThat(request0.method()).isEqualTo(HttpMethod.GET);
		assertThat(getBody(request0)).isEmpty();
	}

	@Test
	public void filterWhenNotExpiredThenShouldRefreshFalse() {
		OAuth2RefreshToken refreshToken = new OAuth2RefreshToken("refresh-token", this.accessToken.getIssuedAt());
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration,
				"principalName", this.accessToken, refreshToken);

		ClientRequest request = ClientRequest.create(GET, URI.create("https://example.com"))
				.attributes(oauth2AuthorizedClient(authorizedClient))
				.attributes(httpServletRequest(new MockHttpServletRequest()))
				.attributes(httpServletResponse(new MockHttpServletResponse()))
				.build();

		this.function.filter(request, this.exchange).block();

		List<ClientRequest> requests = this.exchange.getRequests();
		assertThat(requests).hasSize(1);

		ClientRequest request0 = requests.get(0);
		assertThat(request0.headers().getFirst(HttpHeaders.AUTHORIZATION)).isEqualTo("Bearer token-0");
		assertThat(request0.url().toASCIIString()).isEqualTo("https://example.com");
		assertThat(request0.method()).isEqualTo(HttpMethod.GET);
		assertThat(getBody(request0)).isEmpty();
	}

	// gh-6483
	@Test
	public void filterWhenChainedThenDefaultsStillAvailable() throws Exception {
		this.function.afterPropertiesSet();			// Hooks.onLastOperator() initialized
		this.function.setDefaultOAuth2AuthorizedClient(true);

		MockHttpServletRequest servletRequest = new MockHttpServletRequest();
		MockHttpServletResponse servletResponse = new MockHttpServletResponse();
		RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(servletRequest, servletResponse));

		OAuth2User user = mock(OAuth2User.class);
		List<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList("ROLE_USER");
		OAuth2AuthenticationToken authentication = new OAuth2AuthenticationToken(
				user, authorities, this.registration.getRegistrationId());
		SecurityContextHolder.getContext().setAuthentication(authentication);

		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(
				this.registration, "principalName", this.accessToken);

		when(this.authorizedClientRepository.loadAuthorizedClient(eq(authentication.getAuthorizedClientRegistrationId()),
				eq(authentication), eq(servletRequest))).thenReturn(authorizedClient);

		when(this.clientRegistrationRepository.findByRegistrationId(eq(authentication.getAuthorizedClientRegistrationId()))).thenReturn(this.registration);

		// Default request attributes set
		final ClientRequest request1 = ClientRequest.create(GET, URI.create("https://example1.com"))
				.attributes(attrs -> attrs.putAll(getDefaultRequestAttributes())).build();

		// Default request attributes NOT set
		final ClientRequest request2 = ClientRequest.create(GET, URI.create("https://example2.com")).build();

		this.function.filter(request1, this.exchange)
				.flatMap(response -> this.function.filter(request2, this.exchange))
				.block();

		this.function.destroy();		// Hooks.onLastOperator() released

		List<ClientRequest> requests = this.exchange.getRequests();
		assertThat(requests).hasSize(2);

		ClientRequest request = requests.get(0);
		assertThat(request.headers().getFirst(HttpHeaders.AUTHORIZATION)).isEqualTo("Bearer token-0");
		assertThat(request.url().toASCIIString()).isEqualTo("https://example1.com");
		assertThat(request.method()).isEqualTo(HttpMethod.GET);
		assertThat(getBody(request)).isEmpty();

		request = requests.get(1);
		assertThat(request.headers().getFirst(HttpHeaders.AUTHORIZATION)).isEqualTo("Bearer token-0");
		assertThat(request.url().toASCIIString()).isEqualTo("https://example2.com");
		assertThat(request.method()).isEqualTo(HttpMethod.GET);
		assertThat(getBody(request)).isEmpty();
	}

	@Test
	public void filterWhenRequestAttributesNotSetAndHooksNotInitThenDefaultsNotAvailable() throws Exception {
//		this.function.afterPropertiesSet();		// Hooks.onLastOperator() NOT initialized
		this.function.setDefaultOAuth2AuthorizedClient(true);

		MockHttpServletRequest servletRequest = new MockHttpServletRequest();
		MockHttpServletResponse servletResponse = new MockHttpServletResponse();
		RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(servletRequest, servletResponse));

		OAuth2User user = mock(OAuth2User.class);
		List<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList("ROLE_USER");
		OAuth2AuthenticationToken authentication = new OAuth2AuthenticationToken(
				user, authorities, this.registration.getRegistrationId());
		SecurityContextHolder.getContext().setAuthentication(authentication);

		ClientRequest request = ClientRequest.create(GET, URI.create("https://example.com")).build();

		this.function.filter(request, this.exchange).block();

		List<ClientRequest> requests = this.exchange.getRequests();
		assertThat(requests).hasSize(1);

		request = requests.get(0);
		assertThat(request.headers().getFirst(HttpHeaders.AUTHORIZATION)).isNull();
		assertThat(request.url().toASCIIString()).isEqualTo("https://example.com");
		assertThat(request.method()).isEqualTo(HttpMethod.GET);
		assertThat(getBody(request)).isEmpty();
	}

	@Test
	public void filterWhenRequestAttributesNotSetAndHooksInitHooksResetThenDefaultsNotAvailable() throws Exception {
		this.function.afterPropertiesSet();			// Hooks.onLastOperator() initialized
		this.function.destroy();					// Hooks.onLastOperator() released
		this.function.setDefaultOAuth2AuthorizedClient(true);

		MockHttpServletRequest servletRequest = new MockHttpServletRequest();
		MockHttpServletResponse servletResponse = new MockHttpServletResponse();
		RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(servletRequest, servletResponse));

		OAuth2User user = mock(OAuth2User.class);
		List<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList("ROLE_USER");
		OAuth2AuthenticationToken authentication = new OAuth2AuthenticationToken(
				user, authorities, this.registration.getRegistrationId());
		SecurityContextHolder.getContext().setAuthentication(authentication);

		ClientRequest request = ClientRequest.create(GET, URI.create("https://example.com")).build();

		this.function.filter(request, this.exchange).block();

		List<ClientRequest> requests = this.exchange.getRequests();
		assertThat(requests).hasSize(1);

		request = requests.get(0);
		assertThat(request.headers().getFirst(HttpHeaders.AUTHORIZATION)).isNull();
		assertThat(request.url().toASCIIString()).isEqualTo("https://example.com");
		assertThat(request.method()).isEqualTo(HttpMethod.GET);
		assertThat(getBody(request)).isEmpty();
	}

	// gh-7228
	@Test
	public void afterPropertiesSetWhenHooksInitAndOutsideWebSecurityContextThenShouldNotThrowException() throws Exception {
		this.function.afterPropertiesSet();			// Hooks.onLastOperator() initialized
		assertThatCode(() -> Mono.subscriberContext().block())
				.as("RequestContext Hook brakes application outside of web/security context")
				.doesNotThrowAnyException();
	}

	@Test
	public void createRequestContextSubscriberIfNecessaryWhenOutsideWebSecurityContextThenReturnOriginalSubscriber() throws Exception {
		BaseSubscriber<Object> originalSubscriber = new BaseSubscriber<Object>() {};
		CoreSubscriber<Object> resultSubscriber = this.function.createRequestContextSubscriberIfNecessary(originalSubscriber);
		assertThat(resultSubscriber).isSameAs(originalSubscriber);
	}

	// gh-7228
	@Test
	public void createRequestContextSubscriberWhenRequestResponseProvidedThenCreateWithParentContext() throws Exception {
		testRequestContextSubscriber(new MockHttpServletRequest(), new MockHttpServletResponse(), null);
	}

	// gh-7228
	@Test
	public void createRequestContextSubscriberWhenAuthenticationProvidedThenCreateWithParentContext() throws Exception {
		testRequestContextSubscriber(null, null, this.authentication);
	}

	@Test
	public void createRequestContextSubscriberWhenParentContextHasDataHolderThenShouldReuseParentContext() throws Exception {
		RequestContextDataHolder testValue = new RequestContextDataHolder(null, null, null);
		final Context parentContext = Context.of(RequestContextSubscriber.REQUEST_CONTEXT_DATA_HOLDER, testValue);
		BaseSubscriber<Object> parent = new BaseSubscriber<Object>() {
			@Override
			public Context currentContext() {
				return parentContext;
			}
		};

		RequestContextSubscriber<Object> requestContextSubscriber =
				new RequestContextSubscriber<>(parent, null, null, authentication);

		Context resultContext = requestContextSubscriber.currentContext();

		assertThat(resultContext)
				.describedAs("parent context was replaced")
				.isSameAs(parentContext);
	}

	private void testRequestContextSubscriber(MockHttpServletRequest servletRequest,
											MockHttpServletResponse servletResponse,
											Authentication authentication) {
		String testKey = "test_key";
		String testValue = "test_value";

		BaseSubscriber<Object> parent = new BaseSubscriber<Object>() {
			@Override
			public Context currentContext() {
				return Context.of(testKey, testValue);
			}
		};

		RequestContextSubscriber<Object> requestContextSubscriber =
				new RequestContextSubscriber<>(parent, servletRequest, servletResponse, authentication);

		Context resultContext = requestContextSubscriber.currentContext();

		assertThat(resultContext)
				.describedAs("result context is null")
				.isNotNull();

		assertThat(resultContext.getOrEmpty(testKey))
				.describedAs("context is replaced")
				.hasValue(testValue);

		Object dataHolder = resultContext.getOrDefault(RequestContextSubscriber.REQUEST_CONTEXT_DATA_HOLDER, null);
		assertThat(dataHolder)
				.describedAs("context is not populated with REQUEST_CONTEXT_DATA_HOLDER")
				.isNotNull()
				.hasFieldOrPropertyWithValue("request", servletRequest)
				.hasFieldOrPropertyWithValue("response", servletResponse)
				.hasFieldOrPropertyWithValue("authentication", authentication);
	}

	private static String getBody(ClientRequest request) {
		final List<HttpMessageWriter<?>> messageWriters = new ArrayList<>();
		messageWriters.add(new EncoderHttpMessageWriter<>(new ByteBufferEncoder()));
		messageWriters.add(new EncoderHttpMessageWriter<>(CharSequenceEncoder.textPlainOnly()));
		messageWriters.add(new ResourceHttpMessageWriter());
		Jackson2JsonEncoder jsonEncoder = new Jackson2JsonEncoder();
		messageWriters.add(new EncoderHttpMessageWriter<>(jsonEncoder));
		messageWriters.add(new ServerSentEventHttpMessageWriter(jsonEncoder));
		messageWriters.add(new FormHttpMessageWriter());
		messageWriters.add(new EncoderHttpMessageWriter<>(CharSequenceEncoder.allMimeTypes()));
		messageWriters.add(new MultipartHttpMessageWriter(messageWriters));

		BodyInserter.Context context = new BodyInserter.Context() {
			@Override
			public List<HttpMessageWriter<?>> messageWriters() {
				return messageWriters;
			}

			@Override
			public Optional<ServerHttpRequest> serverRequest() {
				return Optional.empty();
			}

			@Override
			public Map<String, Object> hints() {
				return new HashMap<>();
			}
		};

		MockClientHttpRequest body = new MockClientHttpRequest(HttpMethod.GET, "/");
		request.body().insert(body, context).block();
		return body.getBodyAsString().block();
	}

}
