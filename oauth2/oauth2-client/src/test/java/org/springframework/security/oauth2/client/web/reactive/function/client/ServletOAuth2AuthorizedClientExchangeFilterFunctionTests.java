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
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2ClientCredentialsGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.TestOAuth2AccessTokenResponses;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.reactive.function.BodyInserter;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static org.springframework.http.HttpMethod.GET;
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
	private WebClient.RequestHeadersSpec<?> spec;
	@Captor
	private ArgumentCaptor<Consumer<Map<String, Object>>> attrs;
	@Captor
	private ArgumentCaptor<OAuth2AuthorizedClient> authorizedClientCaptor;

	/**
	 * Used for get the attributes from defaultRequest.
	 */
	private Map<String, Object> result = new HashMap<>();

	private ServletOAuth2AuthorizedClientExchangeFilterFunction function = new ServletOAuth2AuthorizedClientExchangeFilterFunction();

	private MockExchangeFunction exchange = new MockExchangeFunction();

	private Authentication authentication;

	private ClientRegistration registration = TestClientRegistrations.clientRegistration()
			.build();

	private OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
			"token-0",
			Instant.now(),
			Instant.now().plus(Duration.ofDays(1)));

	@Before
	public void setup() {
		this.authentication = new TestingAuthenticationToken("test", "this");
	}

	@After
	public void cleanup() {
		SecurityContextHolder.clearContext();
		RequestContextHolder.resetRequestAttributes();
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
		this.function = new ServletOAuth2AuthorizedClientExchangeFilterFunction(this.clientRegistrationRepository,
				this.authorizedClientRepository);
		SecurityContextHolder.getContext().setAuthentication(this.authentication);
		Map<String, Object> attrs = getDefaultRequestAttributes();
		assertThat(getAuthentication(attrs)).isEqualTo(this.authentication);
		verifyZeroInteractions(this.authorizedClientRepository);
	}

	@Test
	public void defaultRequestOAuth2AuthorizedClientWhenOAuth2AuthorizationClientAndClientIdThenNotOverride() {
		this.function = new ServletOAuth2AuthorizedClientExchangeFilterFunction(this.clientRegistrationRepository,
				this.authorizedClientRepository);
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration,
				"principalName", this.accessToken);
		oauth2AuthorizedClient(authorizedClient).accept(this.result);
		Map<String, Object> attrs = getDefaultRequestAttributes();
		assertThat(getOAuth2AuthorizedClient(attrs)).isEqualTo(authorizedClient);
		verifyZeroInteractions(this.authorizedClientRepository);
	}

	@Test
	public void defaultRequestOAuth2AuthorizedClientWhenAuthenticationNullAndClientRegistrationIdNullThenOAuth2AuthorizedClientNull() {
		this.function = new ServletOAuth2AuthorizedClientExchangeFilterFunction(this.clientRegistrationRepository,
				this.authorizedClientRepository);
		Map<String, Object> attrs = getDefaultRequestAttributes();
		assertThat(getOAuth2AuthorizedClient(attrs)).isNull();
		verifyZeroInteractions(this.authorizedClientRepository);
	}

	@Test
	public void defaultRequestOAuth2AuthorizedClientWhenAuthenticationWrongTypeAndClientRegistrationIdNullThenOAuth2AuthorizedClientNull() {
		this.function = new ServletOAuth2AuthorizedClientExchangeFilterFunction(this.clientRegistrationRepository,
				this.authorizedClientRepository);
		Map<String, Object> attrs = getDefaultRequestAttributes();
		assertThat(getOAuth2AuthorizedClient(attrs)).isNull();
		verifyZeroInteractions(this.authorizedClientRepository);
	}

	@Test
	public void defaultRequestOAuth2AuthorizedClientWhenRepositoryNullThenOAuth2AuthorizedClient() {
		OAuth2User user = mock(OAuth2User.class);
		List<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList("ROLE_USER");
		OAuth2AuthenticationToken token = new OAuth2AuthenticationToken(user, authorities, "id");
		authentication(token).accept(this.result);

		Map<String, Object> attrs = getDefaultRequestAttributes();

		assertThat(getOAuth2AuthorizedClient(attrs)).isNull();
	}

	@Test
	public void defaultRequestOAuth2AuthorizedClientWhenDefaultTrueAndClientRegistrationIdNullThenOAuth2AuthorizedClient() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));
		this.function = new ServletOAuth2AuthorizedClientExchangeFilterFunction(this.clientRegistrationRepository,
				this.authorizedClientRepository);
		this.function.setDefaultOAuth2AuthorizedClient(true);
		OAuth2User user = mock(OAuth2User.class);
		List<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList("ROLE_USER");
		OAuth2AuthenticationToken token = new OAuth2AuthenticationToken(user, authorities, "id");
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration,
				"principalName", this.accessToken);
		when(this.authorizedClientRepository.loadAuthorizedClient(any(), any(), any())).thenReturn(authorizedClient);
		authentication(token).accept(this.result);

		Map<String, Object> attrs = getDefaultRequestAttributes();

		assertThat(getOAuth2AuthorizedClient(attrs)).isEqualTo(authorizedClient);
		verify(this.authorizedClientRepository).loadAuthorizedClient(eq(token.getAuthorizedClientRegistrationId()), any(), any());
	}

	@Test
	public void defaultRequestOAuth2AuthorizedClientWhenDefaultFalseAndAuthenticationAndClientRegistrationIdNullThenOAuth2AuthorizedClient() {
		this.function = new ServletOAuth2AuthorizedClientExchangeFilterFunction(this.clientRegistrationRepository,
				this.authorizedClientRepository);
		OAuth2User user = mock(OAuth2User.class);
		List<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList("ROLE_USER");
		OAuth2AuthenticationToken token = new OAuth2AuthenticationToken(user, authorities, "id");
		authentication(token).accept(this.result);

		Map<String, Object> attrs = getDefaultRequestAttributes();

		assertThat(getOAuth2AuthorizedClient(attrs)).isNull();
	}

	@Test
	public void defaultRequestOAuth2AuthorizedClientWhenAuthenticationAndClientRegistrationIdThenIdIsExplicit() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));
		this.function = new ServletOAuth2AuthorizedClientExchangeFilterFunction(this.clientRegistrationRepository,
				this.authorizedClientRepository);
		OAuth2User user = mock(OAuth2User.class);
		List<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList("ROLE_USER");
		OAuth2AuthenticationToken token = new OAuth2AuthenticationToken(user, authorities, "id");
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration,
				"principalName", this.accessToken);
		when(this.authorizedClientRepository.loadAuthorizedClient(any(), any(), any())).thenReturn(authorizedClient);
		authentication(token).accept(this.result);
		clientRegistrationId("explicit").accept(this.result);

		Map<String, Object> attrs = getDefaultRequestAttributes();

		assertThat(getOAuth2AuthorizedClient(attrs)).isEqualTo(authorizedClient);
		verify(this.authorizedClientRepository).loadAuthorizedClient(eq("explicit"), any(), any());
	}

	@Test
	public void defaultRequestOAuth2AuthorizedClientWhenClientRegistrationIdThenOAuth2AuthorizedClient() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));
		SecurityContextHolder.getContext().setAuthentication(this.authentication);
		this.function = new ServletOAuth2AuthorizedClientExchangeFilterFunction(this.clientRegistrationRepository,
				this.authorizedClientRepository);
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration,
				"principalName", this.accessToken);
		when(this.authorizedClientRepository.loadAuthorizedClient(any(), any(), any())).thenReturn(authorizedClient);
		clientRegistrationId("id").accept(this.result);

		Map<String, Object> attrs = getDefaultRequestAttributes();

		assertThat(getOAuth2AuthorizedClient(attrs)).isEqualTo(authorizedClient);
		verify(this.authorizedClientRepository).loadAuthorizedClient(eq("id"), any(), any());
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
		when(this.exchange.getResponse().body(any())).thenReturn(Mono.just(response));
		Instant issuedAt = Instant.now().minus(Duration.ofDays(1));
		Instant accessTokenExpiresAt = issuedAt.plus(Duration.ofHours(1));

		this.accessToken = new OAuth2AccessToken(this.accessToken.getTokenType(),
				this.accessToken.getTokenValue(),
				issuedAt,
				accessTokenExpiresAt);
		this.function = new ServletOAuth2AuthorizedClientExchangeFilterFunction(this.clientRegistrationRepository,
				this.authorizedClientRepository);

		OAuth2RefreshToken refreshToken = new OAuth2RefreshToken("refresh-token", issuedAt);
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration,
				"principalName", this.accessToken, refreshToken);
		ClientRequest request = ClientRequest.create(GET, URI.create("https://example.com"))
				.attributes(oauth2AuthorizedClient(authorizedClient))
				.attributes(authentication(this.authentication))
				.build();

		this.function.filter(request, this.exchange).block();

		verify(this.authorizedClientRepository).saveAuthorizedClient(this.authorizedClientCaptor.capture(), eq(this.authentication), any(), any());

		OAuth2AuthorizedClient newAuthorizedClient = authorizedClientCaptor.getValue();
		assertThat(newAuthorizedClient.getAccessToken()).isEqualTo(response.getAccessToken());
		assertThat(newAuthorizedClient.getRefreshToken()).isEqualTo(response.getRefreshToken());

		List<ClientRequest> requests = this.exchange.getRequests();
		assertThat(requests).hasSize(2);

		ClientRequest request0 = requests.get(0);
		assertThat(request0.headers().getFirst(HttpHeaders.AUTHORIZATION)).isEqualTo("Basic Y2xpZW50LWlkOmNsaWVudC1zZWNyZXQ=");
		assertThat(request0.url().toASCIIString()).isEqualTo("https://example.com/login/oauth/access_token");
		assertThat(request0.method()).isEqualTo(HttpMethod.POST);
		assertThat(getBody(request0)).isEqualTo("grant_type=refresh_token&refresh_token=refresh-token");

		ClientRequest request1 = requests.get(1);
		assertThat(request1.headers().getFirst(HttpHeaders.AUTHORIZATION)).isEqualTo("Bearer token-1");
		assertThat(request1.url().toASCIIString()).isEqualTo("https://example.com");
		assertThat(request1.method()).isEqualTo(HttpMethod.GET);
		assertThat(getBody(request1)).isEmpty();
	}

	@Test
	public void filterWhenRefreshRequiredThenRefreshAndResponseDoesNotContainRefreshToken() {
		OAuth2AccessTokenResponse response = OAuth2AccessTokenResponse.withToken("token-1")
				.tokenType(OAuth2AccessToken.TokenType.BEARER)
				.expiresIn(3600)
//				.refreshToken(xxx)  // No refreshToken in response
				.build();
		when(this.exchange.getResponse().body(any())).thenReturn(Mono.just(response));
		Instant issuedAt = Instant.now().minus(Duration.ofDays(1));
		Instant accessTokenExpiresAt = issuedAt.plus(Duration.ofHours(1));

		this.accessToken = new OAuth2AccessToken(this.accessToken.getTokenType(),
				this.accessToken.getTokenValue(),
				issuedAt,
				accessTokenExpiresAt);
		this.function = new ServletOAuth2AuthorizedClientExchangeFilterFunction(this.clientRegistrationRepository,
				this.authorizedClientRepository);

		OAuth2RefreshToken refreshToken = new OAuth2RefreshToken("refresh-token", issuedAt);
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration,
				"principalName", this.accessToken, refreshToken);
		ClientRequest request = ClientRequest.create(GET, URI.create("https://example.com"))
				.attributes(oauth2AuthorizedClient(authorizedClient))
				.attributes(authentication(this.authentication))
				.build();

		this.function.filter(request, this.exchange).block();

		verify(this.authorizedClientRepository).saveAuthorizedClient(this.authorizedClientCaptor.capture(), eq(this.authentication), any(), any());

		OAuth2AuthorizedClient newAuthorizedClient = authorizedClientCaptor.getValue();
		assertThat(newAuthorizedClient.getAccessToken()).isEqualTo(response.getAccessToken());
		assertThat(newAuthorizedClient.getRefreshToken()).isEqualTo(refreshToken);

		List<ClientRequest> requests = this.exchange.getRequests();
		assertThat(requests).hasSize(2);

		ClientRequest request0 = requests.get(0);
		assertThat(request0.headers().getFirst(HttpHeaders.AUTHORIZATION)).isEqualTo("Basic Y2xpZW50LWlkOmNsaWVudC1zZWNyZXQ=");
		assertThat(request0.url().toASCIIString()).isEqualTo("https://example.com/login/oauth/access_token");
		assertThat(request0.method()).isEqualTo(HttpMethod.POST);
		assertThat(getBody(request0)).isEqualTo("grant_type=refresh_token&refresh_token=refresh-token");

		ClientRequest request1 = requests.get(1);
		assertThat(request1.headers().getFirst(HttpHeaders.AUTHORIZATION)).isEqualTo("Bearer token-1");
		assertThat(request1.url().toASCIIString()).isEqualTo("https://example.com");
		assertThat(request1.method()).isEqualTo(HttpMethod.GET);
		assertThat(getBody(request1)).isEmpty();
	}

	@Test
	public void filterWhenClientCredentialsTokenNotExpiredThenUseCurrentToken() {
		this.registration = TestClientRegistrations.clientCredentials().build();

		this.function = new ServletOAuth2AuthorizedClientExchangeFilterFunction(this.clientRegistrationRepository,
				this.authorizedClientRepository);
		this.function.setClientCredentialsTokenResponseClient(this.clientCredentialsTokenResponseClient);

		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration,
				"principalName", this.accessToken, null);
		ClientRequest request = ClientRequest.create(GET, URI.create("https://example.com"))
				.attributes(oauth2AuthorizedClient(authorizedClient))
				.attributes(authentication(this.authentication))
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
		this.function = new ServletOAuth2AuthorizedClientExchangeFilterFunction(this.clientRegistrationRepository,
				this.authorizedClientRepository);
		this.function.setClientCredentialsTokenResponseClient(this.clientCredentialsTokenResponseClient);

		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration,
				"principalName", this.accessToken, null);
		ClientRequest request = ClientRequest.create(GET, URI.create("https://example.com"))
				.attributes(oauth2AuthorizedClient(authorizedClient))
				.attributes(authentication(this.authentication))
				.build();

		this.function.filter(request, this.exchange).block();

		verify(this.authorizedClientRepository).saveAuthorizedClient(any(), eq(this.authentication), any(), any());

		verify(clientCredentialsTokenResponseClient).getTokenResponse(any());

		List<ClientRequest> requests = this.exchange.getRequests();
		assertThat(requests).hasSize(1);

		ClientRequest request1 = requests.get(0);
		assertThat(request1.headers().getFirst(HttpHeaders.AUTHORIZATION)).isEqualTo("Bearer token");
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
		when(this.exchange.getResponse().body(any())).thenReturn(Mono.just(response));
		Instant issuedAt = Instant.now().minus(Duration.ofDays(1));
		Instant accessTokenExpiresAt = issuedAt.plus(Duration.ofHours(1));

		this.accessToken = new OAuth2AccessToken(this.accessToken.getTokenType(),
				this.accessToken.getTokenValue(),
				issuedAt,
				accessTokenExpiresAt);
		this.function = new ServletOAuth2AuthorizedClientExchangeFilterFunction(this.clientRegistrationRepository,
				this.authorizedClientRepository);

		OAuth2RefreshToken refreshToken = new OAuth2RefreshToken("refresh-token", issuedAt);
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration,
				"principalName", this.accessToken, refreshToken);
		ClientRequest request = ClientRequest.create(GET, URI.create("https://example.com"))
				.attributes(oauth2AuthorizedClient(authorizedClient))
				.build();

		this.function.filter(request, this.exchange)
				.block();

		verify(this.authorizedClientRepository).saveAuthorizedClient(any(), any(), any(), any());

		List<ClientRequest> requests = this.exchange.getRequests();
		assertThat(requests).hasSize(2);

		ClientRequest request0 = requests.get(0);
		assertThat(request0.headers().getFirst(HttpHeaders.AUTHORIZATION)).isEqualTo("Basic Y2xpZW50LWlkOmNsaWVudC1zZWNyZXQ=");
		assertThat(request0.url().toASCIIString()).isEqualTo("https://example.com/login/oauth/access_token");
		assertThat(request0.method()).isEqualTo(HttpMethod.POST);
		assertThat(getBody(request0)).isEqualTo("grant_type=refresh_token&refresh_token=refresh-token");

		ClientRequest request1 = requests.get(1);
		assertThat(request1.headers().getFirst(HttpHeaders.AUTHORIZATION)).isEqualTo("Bearer token-1");
		assertThat(request1.url().toASCIIString()).isEqualTo("https://example.com");
		assertThat(request1.method()).isEqualTo(HttpMethod.GET);
		assertThat(getBody(request1)).isEmpty();
	}

	@Test
	public void filterWhenRefreshTokenNullThenShouldRefreshFalse() {
		this.function = new ServletOAuth2AuthorizedClientExchangeFilterFunction(this.clientRegistrationRepository,
				this.authorizedClientRepository);

		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration,
				"principalName", this.accessToken);
		ClientRequest request = ClientRequest.create(GET, URI.create("https://example.com"))
				.attributes(oauth2AuthorizedClient(authorizedClient))
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
		this.function = new ServletOAuth2AuthorizedClientExchangeFilterFunction(this.clientRegistrationRepository,
				this.authorizedClientRepository);

		OAuth2RefreshToken refreshToken = new OAuth2RefreshToken("refresh-token", this.accessToken.getIssuedAt());
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration,
				"principalName", this.accessToken, refreshToken);
		ClientRequest request = ClientRequest.create(GET, URI.create("https://example.com"))
				.attributes(oauth2AuthorizedClient(authorizedClient))
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
		this.function = new ServletOAuth2AuthorizedClientExchangeFilterFunction(
				this.clientRegistrationRepository, this.authorizedClientRepository);
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
		this.function = new ServletOAuth2AuthorizedClientExchangeFilterFunction(
				this.clientRegistrationRepository, this.authorizedClientRepository);
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
		this.function = new ServletOAuth2AuthorizedClientExchangeFilterFunction(
				this.clientRegistrationRepository, this.authorizedClientRepository);
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
