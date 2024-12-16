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

package org.springframework.security.oauth2.client.web.reactive.function.client;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.util.context.Context;

import org.springframework.core.codec.ByteBufferEncoder;
import org.springframework.core.codec.CharSequenceEncoder;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.codec.EncoderHttpMessageWriter;
import org.springframework.http.codec.FormHttpMessageWriter;
import org.springframework.http.codec.HttpMessageWriter;
import org.springframework.http.codec.ResourceHttpMessageWriter;
import org.springframework.http.codec.ServerSentEventHttpMessageWriter;
import org.springframework.http.codec.json.Jackson2JsonEncoder;
import org.springframework.http.codec.multipart.MultipartHttpMessageWriter;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.mock.http.client.reactive.MockClientHttpRequest;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.client.ClientAuthorizationException;
import org.springframework.security.oauth2.client.JwtBearerOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizationFailureHandler;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.RefreshTokenOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.endpoint.JwtBearerGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2ClientCredentialsGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2PasswordGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequest;
import org.springframework.security.oauth2.client.endpoint.RestClientRefreshTokenTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.TestOAuth2AccessTokenResponses;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.TestJwts;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestClient;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.reactive.function.BodyInserter;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.entry;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

/**
 * @author Rob Winch
 * @since 5.1
 */
@ExtendWith(MockitoExtension.class)
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
	private OAuth2AccessTokenResponseClient<JwtBearerGrantRequest> jwtBearerTokenResponseClient;

	@Mock
	private OAuth2AuthorizationFailureHandler authorizationFailureHandler;

	@Captor
	private ArgumentCaptor<OAuth2AuthorizationException> authorizationExceptionCaptor;

	@Captor
	private ArgumentCaptor<Authentication> authenticationCaptor;

	@Captor
	private ArgumentCaptor<Map<String, Object>> attributesCaptor;

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

	private OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "token-0",
			Instant.now(), Instant.now().plus(Duration.ofDays(1)));

	@BeforeEach
	public void setup() {
		this.authentication = new TestingAuthenticationToken("test", "this");
		JwtBearerOAuth2AuthorizedClientProvider jwtBearerAuthorizedClientProvider = new JwtBearerOAuth2AuthorizedClientProvider();
		jwtBearerAuthorizedClientProvider.setAccessTokenResponseClient(this.jwtBearerTokenResponseClient);
		// @formatter:off
		OAuth2AuthorizedClientProvider authorizedClientProvider = OAuth2AuthorizedClientProviderBuilder.builder()
				.authorizationCode()
				.refreshToken(
						(configurer) -> configurer.accessTokenResponseClient(this.refreshTokenTokenResponseClient))
				.clientCredentials(
						(configurer) -> configurer.accessTokenResponseClient(this.clientCredentialsTokenResponseClient))
				.password((configurer) -> configurer.accessTokenResponseClient(this.passwordTokenResponseClient))
				.provider(jwtBearerAuthorizedClientProvider)
				.build();
		// @formatter:on
		this.authorizedClientManager = new DefaultOAuth2AuthorizedClientManager(this.clientRegistrationRepository,
				this.authorizedClientRepository);
		this.authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);
		this.function = new ServletOAuth2AuthorizedClientExchangeFilterFunction(this.authorizedClientManager);
	}

	@AfterEach
	public void cleanup() throws Exception {
		SecurityContextHolder.clearContext();
		RequestContextHolder.resetRequestAttributes();
	}

	@Test
	public void constructorWhenAuthorizedClientManagerIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> new ServletOAuth2AuthorizedClientExchangeFilterFunction(null));
	}

	@Test
	public void defaultRequestRequestResponseWhenNullRequestContextThenRequestAndResponseNull() {
		Map<String, Object> attrs = getDefaultRequestAttributes();
		assertThat(ServletOAuth2AuthorizedClientExchangeFilterFunction.getRequest(attrs)).isNull();
		assertThat(ServletOAuth2AuthorizedClientExchangeFilterFunction.getResponse(attrs)).isNull();
	}

	@Test
	public void defaultRequestRequestResponseWhenRequestContextThenRequestAndResponseSet() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));
		Map<String, Object> attrs = getDefaultRequestAttributes();
		assertThat(ServletOAuth2AuthorizedClientExchangeFilterFunction.getRequest(attrs)).isEqualTo(request);
		assertThat(ServletOAuth2AuthorizedClientExchangeFilterFunction.getResponse(attrs)).isEqualTo(response);
	}

	@Test
	public void defaultRequestAuthenticationWhenSecurityContextEmptyThenAuthenticationNull() {
		Map<String, Object> attrs = getDefaultRequestAttributes();
		assertThat(ServletOAuth2AuthorizedClientExchangeFilterFunction.getAuthentication(attrs)).isNull();
	}

	@Test
	public void defaultRequestAuthenticationWhenAuthenticationSetThenAuthenticationSet() {
		SecurityContextHolder.getContext().setAuthentication(this.authentication);
		Map<String, Object> attrs = getDefaultRequestAttributes();
		assertThat(ServletOAuth2AuthorizedClientExchangeFilterFunction.getAuthentication(attrs))
			.isEqualTo(this.authentication);
		verifyNoInteractions(this.authorizedClientRepository);
	}

	@Test
	public void defaultRequestAuthenticationWhenCustomSecurityContextHolderStrategyThenAuthenticationSet() {
		SecurityContextHolderStrategy strategy = mock(SecurityContextHolderStrategy.class);
		given(strategy.getContext()).willReturn(new SecurityContextImpl(this.authentication));
		this.function.setSecurityContextHolderStrategy(strategy);
		Map<String, Object> attrs = getDefaultRequestAttributes();
		assertThat(ServletOAuth2AuthorizedClientExchangeFilterFunction.getAuthentication(attrs))
			.isEqualTo(this.authentication);
		verify(strategy).getContext();
		verifyNoInteractions(this.authorizedClientRepository);
	}

	private Map<String, Object> getDefaultRequestAttributes() {
		this.function.defaultRequest().accept(this.spec);
		verify(this.spec).attributes(this.attrs.capture());
		this.attrs.getValue().accept(this.result);
		return this.result;
	}

	@Test
	public void filterWhenAuthorizedClientNullThenAuthorizationHeaderNull() {
		ClientRequest request = ClientRequest.create(HttpMethod.GET, URI.create("https://example.com")).build();
		this.function.filter(request, this.exchange).block();
		assertThat(this.exchange.getRequest().headers().getFirst(HttpHeaders.AUTHORIZATION)).isNull();
	}

	@Test
	public void filterWhenAuthorizedClientThenAuthorizationHeader() {
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration, "principalName",
				this.accessToken);
		ClientRequest request = ClientRequest.create(HttpMethod.GET, URI.create("https://example.com"))
			.attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient(authorizedClient))
			.attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction
				.httpServletRequest(new MockHttpServletRequest()))
			.attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction
				.httpServletResponse(new MockHttpServletResponse()))
			.build();
		this.function.filter(request, this.exchange).block();
		assertThat(this.exchange.getRequest().headers().getFirst(HttpHeaders.AUTHORIZATION))
			.isEqualTo("Bearer " + this.accessToken.getTokenValue());
	}

	@Test
	public void filterWhenExistingAuthorizationThenSingleAuthorizationHeader() {
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration, "principalName",
				this.accessToken);
		ClientRequest request = ClientRequest.create(HttpMethod.GET, URI.create("https://example.com"))
			.header(HttpHeaders.AUTHORIZATION, "Existing")
			.attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient(authorizedClient))
			.attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction
				.httpServletRequest(new MockHttpServletRequest()))
			.attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction
				.httpServletResponse(new MockHttpServletResponse()))
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
		given(this.refreshTokenTokenResponseClient.getTokenResponse(any())).willReturn(response);
		Instant issuedAt = Instant.now().minus(Duration.ofDays(1));
		Instant accessTokenExpiresAt = issuedAt.plus(Duration.ofHours(1));
		this.accessToken = new OAuth2AccessToken(this.accessToken.getTokenType(), this.accessToken.getTokenValue(),
				issuedAt, accessTokenExpiresAt);
		OAuth2RefreshToken refreshToken = new OAuth2RefreshToken("refresh-token", issuedAt);
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration, "principalName",
				this.accessToken, refreshToken);
		ClientRequest request = ClientRequest.create(HttpMethod.GET, URI.create("https://example.com"))
			.attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient(authorizedClient))
			.attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction.authentication(this.authentication))
			.attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction
				.httpServletRequest(new MockHttpServletRequest()))
			.attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction
				.httpServletResponse(new MockHttpServletResponse()))
			.build();
		this.function.filter(request, this.exchange).block();
		verify(this.refreshTokenTokenResponseClient).getTokenResponse(any());
		verify(this.authorizedClientRepository).saveAuthorizedClient(this.authorizedClientCaptor.capture(),
				eq(this.authentication), any(), any());
		OAuth2AuthorizedClient newAuthorizedClient = this.authorizedClientCaptor.getValue();
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
			// .refreshToken(xxx) // No refreshToken in response
			.build();
		RestClient.Builder builder = RestClient.builder().messageConverters((messageConverters) -> {
			messageConverters.clear();
			messageConverters.add(new FormHttpMessageConverter());
			messageConverters.add(new OAuth2AccessTokenResponseHttpMessageConverter());
		});
		MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
		RestClient refreshTokenClient = builder.build();
		server.expect(requestTo("https://example.com/login/oauth/access_token"))
			.andRespond(withSuccess().header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
				.body(new ClassPathResource("access-token-response-1.json")));
		RestClientRefreshTokenTokenResponseClient refreshTokenTokenResponseClient = new RestClientRefreshTokenTokenResponseClient();
		refreshTokenTokenResponseClient.setRestClient(refreshTokenClient);
		RefreshTokenOAuth2AuthorizedClientProvider authorizedClientProvider = new RefreshTokenOAuth2AuthorizedClientProvider();
		authorizedClientProvider.setAccessTokenResponseClient(refreshTokenTokenResponseClient);
		DefaultOAuth2AuthorizedClientManager authorizedClientManager = new DefaultOAuth2AuthorizedClientManager(
				this.clientRegistrationRepository, this.authorizedClientRepository);
		authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);
		this.function = new ServletOAuth2AuthorizedClientExchangeFilterFunction(authorizedClientManager);
		Instant issuedAt = Instant.now().minus(Duration.ofDays(1));
		Instant accessTokenExpiresAt = issuedAt.plus(Duration.ofHours(1));
		this.accessToken = new OAuth2AccessToken(this.accessToken.getTokenType(), this.accessToken.getTokenValue(),
				issuedAt, accessTokenExpiresAt);
		OAuth2RefreshToken refreshToken = new OAuth2RefreshToken("refresh-token", issuedAt);
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration, "principalName",
				this.accessToken, refreshToken);
		ClientRequest request = ClientRequest.create(HttpMethod.GET, URI.create("https://example.com"))
			.attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient(authorizedClient))
			.attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction.authentication(this.authentication))
			.attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction
				.httpServletRequest(new MockHttpServletRequest()))
			.attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction
				.httpServletResponse(new MockHttpServletResponse()))
			.build();
		this.function.filter(request, this.exchange).block();
		server.verify();
		verify(this.authorizedClientRepository).saveAuthorizedClient(this.authorizedClientCaptor.capture(),
				eq(this.authentication), any(), any());
		OAuth2AuthorizedClient newAuthorizedClient = this.authorizedClientCaptor.getValue();
		assertThat(newAuthorizedClient.getAccessToken().getTokenValue())
			.isEqualTo(response.getAccessToken().getTokenValue());
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
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration, "principalName",
				this.accessToken, null);
		ClientRequest request = ClientRequest.create(HttpMethod.GET, URI.create("https://example.com"))
			.attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient(authorizedClient))
			.attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction.authentication(this.authentication))
			.attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction
				.httpServletRequest(new MockHttpServletRequest()))
			.attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction
				.httpServletResponse(new MockHttpServletResponse()))
			.build();
		this.function.filter(request, this.exchange).block();
		verify(this.authorizedClientRepository, never()).saveAuthorizedClient(any(), eq(this.authentication), any(),
				any());
		verify(this.clientCredentialsTokenResponseClient, never()).getTokenResponse(any());
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
		OAuth2AccessTokenResponse accessTokenResponse = TestOAuth2AccessTokenResponses.accessTokenResponse().build();
		given(this.clientCredentialsTokenResponseClient.getTokenResponse(any())).willReturn(accessTokenResponse);
		Instant issuedAt = Instant.now().minus(Duration.ofDays(1));
		Instant accessTokenExpiresAt = issuedAt.plus(Duration.ofHours(1));
		this.accessToken = new OAuth2AccessToken(this.accessToken.getTokenType(), this.accessToken.getTokenValue(),
				issuedAt, accessTokenExpiresAt);
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration, "principalName",
				this.accessToken, null);
		ClientRequest request = ClientRequest.create(HttpMethod.GET, URI.create("https://example.com"))
			.attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient(authorizedClient))
			.attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction.authentication(this.authentication))
			.attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction
				.httpServletRequest(new MockHttpServletRequest()))
			.attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction
				.httpServletResponse(new MockHttpServletResponse()))
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
		given(this.passwordTokenResponseClient.getTokenResponse(any())).willReturn(accessTokenResponse);
		ClientRegistration registration = TestClientRegistrations.password().build();
		given(this.clientRegistrationRepository.findByRegistrationId(eq(registration.getRegistrationId())))
			.willReturn(registration);
		// Set custom contextAttributesMapper
		this.authorizedClientManager.setContextAttributesMapper((authorizeRequest) -> {
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
		ClientRequest request = ClientRequest.create(HttpMethod.GET, URI.create("https://example.com"))
			.attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction
				.clientRegistrationId(registration.getRegistrationId()))
			.attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction.authentication(this.authentication))
			.attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction.httpServletRequest(servletRequest))
			.attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction.httpServletResponse(servletResponse))
			.build();
		this.function.filter(request, this.exchange).block();
		verify(this.passwordTokenResponseClient).getTokenResponse(any());
		verify(this.authorizedClientRepository).saveAuthorizedClient(any(), eq(this.authentication), any(), any());
		List<ClientRequest> requests = this.exchange.getRequests();
		assertThat(requests).hasSize(1);
		ClientRequest request1 = requests.get(0);
		assertThat(request1.headers().getFirst(HttpHeaders.AUTHORIZATION)).isEqualTo("Bearer new-token");
		assertThat(request1.url().toASCIIString()).isEqualTo("https://example.com");
		assertThat(request1.method()).isEqualTo(HttpMethod.GET);
		assertThat(getBody(request1)).isEmpty();
	}

	@Test
	public void filterWhenJwtBearerClientNotAuthorizedThenExchangeToken() {
		OAuth2AccessTokenResponse accessTokenResponse = OAuth2AccessTokenResponse.withToken("exchanged-token")
			.tokenType(OAuth2AccessToken.TokenType.BEARER)
			.expiresIn(360)
			.build();
		given(this.jwtBearerTokenResponseClient.getTokenResponse(any())).willReturn(accessTokenResponse);
		// @formatter:off
		ClientRegistration registration = ClientRegistration.withRegistrationId("jwt-bearer")
				.clientId("client-id")
				.clientSecret("client-secret")
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.JWT_BEARER)
				.scope("read", "write")
				.tokenUri("https://example.com/oauth/token")
				.build();
		// @formatter:on
		given(this.clientRegistrationRepository.findByRegistrationId(eq(registration.getRegistrationId())))
			.willReturn(registration);
		Jwt jwtAssertion = TestJwts.jwt().build();
		Authentication jwtAuthentication = new TestingAuthenticationToken(jwtAssertion, jwtAssertion);
		MockHttpServletRequest servletRequest = new MockHttpServletRequest();
		MockHttpServletResponse servletResponse = new MockHttpServletResponse();
		ClientRequest request = ClientRequest.create(HttpMethod.GET, URI.create("https://example.com"))
			.attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction
				.clientRegistrationId(registration.getRegistrationId()))
			.attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction.authentication(jwtAuthentication))
			.attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction.httpServletRequest(servletRequest))
			.attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction.httpServletResponse(servletResponse))
			.build();
		this.function.filter(request, this.exchange).block();
		verify(this.jwtBearerTokenResponseClient).getTokenResponse(any());
		verify(this.authorizedClientRepository).saveAuthorizedClient(any(), eq(jwtAuthentication), any(), any());
		List<ClientRequest> requests = this.exchange.getRequests();
		assertThat(requests).hasSize(1);
		ClientRequest request1 = requests.get(0);
		assertThat(request1.headers().getFirst(HttpHeaders.AUTHORIZATION)).isEqualTo("Bearer exchanged-token");
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
		given(this.refreshTokenTokenResponseClient.getTokenResponse(any())).willReturn(response);
		Instant issuedAt = Instant.now().minus(Duration.ofDays(1));
		Instant accessTokenExpiresAt = issuedAt.plus(Duration.ofHours(1));
		this.accessToken = new OAuth2AccessToken(this.accessToken.getTokenType(), this.accessToken.getTokenValue(),
				issuedAt, accessTokenExpiresAt);
		OAuth2RefreshToken refreshToken = new OAuth2RefreshToken("refresh-token", issuedAt);
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration, "principalName",
				this.accessToken, refreshToken);
		ClientRequest request = ClientRequest.create(HttpMethod.GET, URI.create("https://example.com"))
			.attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient(authorizedClient))
			.attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction
				.httpServletRequest(new MockHttpServletRequest()))
			.attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction
				.httpServletResponse(new MockHttpServletResponse()))
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
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration, "principalName",
				this.accessToken);
		ClientRequest request = ClientRequest.create(HttpMethod.GET, URI.create("https://example.com"))
			.attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient(authorizedClient))
			.attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction
				.httpServletRequest(new MockHttpServletRequest()))
			.attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction
				.httpServletResponse(new MockHttpServletResponse()))
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
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration, "principalName",
				this.accessToken, refreshToken);
		ClientRequest request = ClientRequest.create(HttpMethod.GET, URI.create("https://example.com"))
			.attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient(authorizedClient))
			.attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction
				.httpServletRequest(new MockHttpServletRequest()))
			.attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction
				.httpServletResponse(new MockHttpServletResponse()))
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
		this.function.setDefaultOAuth2AuthorizedClient(true);
		MockHttpServletRequest servletRequest = new MockHttpServletRequest();
		MockHttpServletResponse servletResponse = new MockHttpServletResponse();
		OAuth2User user = mock(OAuth2User.class);
		List<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList("ROLE_USER");
		OAuth2AuthenticationToken authentication = new OAuth2AuthenticationToken(user, authorities,
				this.registration.getRegistrationId());
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration, "principalName",
				this.accessToken);
		given(this.authorizedClientRepository.loadAuthorizedClient(
				eq(authentication.getAuthorizedClientRegistrationId()), eq(authentication), eq(servletRequest)))
			.willReturn(authorizedClient);
		// Default request attributes set
		final ClientRequest request1 = ClientRequest.create(HttpMethod.GET, URI.create("https://example1.com"))
			.attributes((attrs) -> attrs.putAll(getDefaultRequestAttributes()))
			.build();
		// Default request attributes NOT set
		final ClientRequest request2 = ClientRequest.create(HttpMethod.GET, URI.create("https://example2.com")).build();
		Context context = context(servletRequest, servletResponse, authentication);
		this.function.filter(request1, this.exchange)
			.flatMap((response) -> this.function.filter(request2, this.exchange))
			.contextWrite(context)
			.block();
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
	public void filterWhenUnauthorizedThenInvokeFailureHandler() {
		assertHttpStatusInvokesFailureHandler(HttpStatus.UNAUTHORIZED, OAuth2ErrorCodes.INVALID_TOKEN);
	}

	@Test
	public void filterWhenForbiddenThenInvokeFailureHandler() {
		assertHttpStatusInvokesFailureHandler(HttpStatus.FORBIDDEN, OAuth2ErrorCodes.INSUFFICIENT_SCOPE);
	}

	private void assertHttpStatusInvokesFailureHandler(HttpStatus httpStatus, String expectedErrorCode) {
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration, "principalName",
				this.accessToken);
		MockHttpServletRequest servletRequest = new MockHttpServletRequest();
		MockHttpServletResponse servletResponse = new MockHttpServletResponse();
		ClientRequest request = ClientRequest.create(HttpMethod.GET, URI.create("https://example.com"))
			.attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient(authorizedClient))
			.attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction.httpServletRequest(servletRequest))
			.attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction.httpServletResponse(servletResponse))
			.build();
		given(this.exchange.getResponse().statusCode()).willReturn(httpStatus);
		given(this.exchange.getResponse().headers()).willReturn(mock(ClientResponse.Headers.class));
		this.function.setAuthorizationFailureHandler(this.authorizationFailureHandler);
		this.function.filter(request, this.exchange).block();
		verify(this.authorizationFailureHandler).onAuthorizationFailure(this.authorizationExceptionCaptor.capture(),
				this.authenticationCaptor.capture(), this.attributesCaptor.capture());
		assertThat(this.authorizationExceptionCaptor.getValue())
			.isInstanceOfSatisfying(ClientAuthorizationException.class, (ex) -> {
				assertThat(ex.getClientRegistrationId()).isEqualTo(this.registration.getRegistrationId());
				assertThat(ex.getError().getErrorCode()).isEqualTo(expectedErrorCode);
				assertThat(ex).hasNoCause();
				assertThat(ex).hasMessageContaining(expectedErrorCode);
			});
		assertThat(this.authenticationCaptor.getValue().getName()).isEqualTo(authorizedClient.getPrincipalName());
		assertThat(this.attributesCaptor.getValue()).containsExactly(
				entry(HttpServletRequest.class.getName(), servletRequest),
				entry(HttpServletResponse.class.getName(), servletResponse));
	}

	@Test
	public void filterWhenWWWAuthenticateHeaderIncludesErrorThenInvokeFailureHandler() {
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration, "principalName",
				this.accessToken);
		MockHttpServletRequest servletRequest = new MockHttpServletRequest();
		MockHttpServletResponse servletResponse = new MockHttpServletResponse();
		ClientRequest request = ClientRequest.create(HttpMethod.GET, URI.create("https://example.com"))
			.attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient(authorizedClient))
			.attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction.httpServletRequest(servletRequest))
			.attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction.httpServletResponse(servletResponse))
			.build();
		String wwwAuthenticateHeader = "Bearer error=\"insufficient_scope\", "
				+ "error_description=\"The request requires higher privileges than provided by the access token.\", "
				+ "error_uri=\"https://tools.ietf.org/html/rfc6750#section-3.1\"";
		ClientResponse.Headers headers = mock(ClientResponse.Headers.class);
		given(headers.header(eq(HttpHeaders.WWW_AUTHENTICATE)))
			.willReturn(Collections.singletonList(wwwAuthenticateHeader));
		given(this.exchange.getResponse().headers()).willReturn(headers);
		this.function.setAuthorizationFailureHandler(this.authorizationFailureHandler);
		this.function.filter(request, this.exchange).block();
		verify(this.authorizationFailureHandler).onAuthorizationFailure(this.authorizationExceptionCaptor.capture(),
				this.authenticationCaptor.capture(), this.attributesCaptor.capture());
		assertThat(this.authorizationExceptionCaptor.getValue())
			.isInstanceOfSatisfying(ClientAuthorizationException.class, (ex) -> {
				assertThat(ex.getClientRegistrationId()).isEqualTo(this.registration.getRegistrationId());
				assertThat(ex.getError().getErrorCode()).isEqualTo(OAuth2ErrorCodes.INSUFFICIENT_SCOPE);
				assertThat(ex.getError().getDescription())
					.isEqualTo("The request requires higher privileges than provided by the access token.");
				assertThat(ex.getError().getUri()).isEqualTo("https://tools.ietf.org/html/rfc6750#section-3.1");
				assertThat(ex).hasNoCause();
				assertThat(ex).hasMessageContaining(OAuth2ErrorCodes.INSUFFICIENT_SCOPE);
			});
		assertThat(this.authenticationCaptor.getValue().getName()).isEqualTo(authorizedClient.getPrincipalName());
		assertThat(this.attributesCaptor.getValue()).containsExactly(
				entry(HttpServletRequest.class.getName(), servletRequest),
				entry(HttpServletResponse.class.getName(), servletResponse));
	}

	@Test
	public void filterWhenUnauthorizedWithWebClientExceptionThenInvokeFailureHandler() {
		assertHttpStatusWithWebClientExceptionInvokesFailureHandler(HttpStatus.UNAUTHORIZED,
				OAuth2ErrorCodes.INVALID_TOKEN);
	}

	@Test
	public void filterWhenForbiddenWithWebClientExceptionThenInvokeFailureHandler() {
		assertHttpStatusWithWebClientExceptionInvokesFailureHandler(HttpStatus.FORBIDDEN,
				OAuth2ErrorCodes.INSUFFICIENT_SCOPE);
	}

	private void assertHttpStatusWithWebClientExceptionInvokesFailureHandler(HttpStatus httpStatus,
			String expectedErrorCode) {
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration, "principalName",
				this.accessToken);
		MockHttpServletRequest servletRequest = new MockHttpServletRequest();
		MockHttpServletResponse servletResponse = new MockHttpServletResponse();
		ClientRequest request = ClientRequest.create(HttpMethod.GET, URI.create("https://example.com"))
			.attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient(authorizedClient))
			.attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction.httpServletRequest(servletRequest))
			.attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction.httpServletResponse(servletResponse))
			.build();
		WebClientResponseException exception = WebClientResponseException.create(httpStatus.value(),
				httpStatus.getReasonPhrase(), HttpHeaders.EMPTY, new byte[0], StandardCharsets.UTF_8);
		ExchangeFunction throwingExchangeFunction = (r) -> Mono.error(exception);
		this.function.setAuthorizationFailureHandler(this.authorizationFailureHandler);
		assertThatExceptionOfType(WebClientResponseException.class)
			.isThrownBy(() -> this.function.filter(request, throwingExchangeFunction).block())
			.isEqualTo(exception);
		verify(this.authorizationFailureHandler).onAuthorizationFailure(this.authorizationExceptionCaptor.capture(),
				this.authenticationCaptor.capture(), this.attributesCaptor.capture());
		assertThat(this.authorizationExceptionCaptor.getValue())
			.isInstanceOfSatisfying(ClientAuthorizationException.class, (ex) -> {
				assertThat(ex.getClientRegistrationId()).isEqualTo(this.registration.getRegistrationId());
				assertThat(ex.getError().getErrorCode()).isEqualTo(expectedErrorCode);
				assertThat(ex).hasCause(exception);
				assertThat(ex).hasMessageContaining(expectedErrorCode);
			});
		assertThat(this.authenticationCaptor.getValue().getName()).isEqualTo(authorizedClient.getPrincipalName());
		assertThat(this.attributesCaptor.getValue()).containsExactly(
				entry(HttpServletRequest.class.getName(), servletRequest),
				entry(HttpServletResponse.class.getName(), servletResponse));
	}

	@Test
	public void filterWhenAuthorizationExceptionThenInvokeFailureHandler() {
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration, "principalName",
				this.accessToken);
		MockHttpServletRequest servletRequest = new MockHttpServletRequest();
		MockHttpServletResponse servletResponse = new MockHttpServletResponse();
		ClientRequest request = ClientRequest.create(HttpMethod.GET, URI.create("https://example.com"))
			.attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient(authorizedClient))
			.attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction.httpServletRequest(servletRequest))
			.attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction.httpServletResponse(servletResponse))
			.build();
		OAuth2AuthorizationException authorizationException = new OAuth2AuthorizationException(
				new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN));
		ExchangeFunction throwingExchangeFunction = (r) -> Mono.error(authorizationException);
		this.function.setAuthorizationFailureHandler(this.authorizationFailureHandler);
		assertThatExceptionOfType(OAuth2AuthorizationException.class)
			.isThrownBy(() -> this.function.filter(request, throwingExchangeFunction).block())
			.isEqualTo(authorizationException);
		verify(this.authorizationFailureHandler).onAuthorizationFailure(this.authorizationExceptionCaptor.capture(),
				this.authenticationCaptor.capture(), this.attributesCaptor.capture());
		assertThat(this.authorizationExceptionCaptor.getValue())
			.isInstanceOfSatisfying(OAuth2AuthorizationException.class, (ex) -> {
				assertThat(ex.getError().getErrorCode()).isEqualTo(authorizationException.getError().getErrorCode());
				assertThat(ex).hasNoCause();
				assertThat(ex).hasMessageContaining(OAuth2ErrorCodes.INVALID_TOKEN);
			});
		assertThat(this.authenticationCaptor.getValue().getName()).isEqualTo(authorizedClient.getPrincipalName());
		assertThat(this.attributesCaptor.getValue()).containsExactly(
				entry(HttpServletRequest.class.getName(), servletRequest),
				entry(HttpServletResponse.class.getName(), servletResponse));
	}

	@Test
	public void filterWhenOtherHttpStatusThenDoesNotInvokeFailureHandler() {
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.registration, "principalName",
				this.accessToken);
		MockHttpServletRequest servletRequest = new MockHttpServletRequest();
		MockHttpServletResponse servletResponse = new MockHttpServletResponse();
		ClientRequest request = ClientRequest.create(HttpMethod.GET, URI.create("https://example.com"))
			.attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient(authorizedClient))
			.attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction.httpServletRequest(servletRequest))
			.attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction.httpServletResponse(servletResponse))
			.build();
		given(this.exchange.getResponse().statusCode()).willReturn(HttpStatus.BAD_REQUEST);
		given(this.exchange.getResponse().headers()).willReturn(mock(ClientResponse.Headers.class));
		this.function.setAuthorizationFailureHandler(this.authorizationFailureHandler);
		this.function.filter(request, this.exchange).block();
		verifyNoInteractions(this.authorizationFailureHandler);
	}

	private Context context(HttpServletRequest servletRequest, HttpServletResponse servletResponse,
			Authentication authentication) {
		Map<Object, Object> contextAttributes = new HashMap<>();
		contextAttributes.put(HttpServletRequest.class, servletRequest);
		contextAttributes.put(HttpServletResponse.class, servletResponse);
		contextAttributes.put(Authentication.class, authentication);
		return Context.of(ServletOAuth2AuthorizedClientExchangeFilterFunction.SECURITY_REACTOR_CONTEXT_ATTRIBUTES_KEY,
				contextAttributes);
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
