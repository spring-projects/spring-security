/*
 * Copyright 2002-2025 the original author or authors.
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

package org.springframework.security.config.annotation.web.configurers.oauth2.client;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.TestOAuth2AccessTokenResponses;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.jwt.TestJwts;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;

/**
 * Tests for {@link OidcUserRefreshedEventListener} with {@link OAuth2LoginConfigurer}.
 *
 * @author Steve Riesenberg
 */
public class OidcUserRefreshedEventListenerConfigurationTests {

	// @formatter:off
	private static final ClientRegistration GOOGLE_CLIENT_REGISTRATION = CommonOAuth2Provider.GOOGLE
			.getBuilder("google")
			.clientId("clientId")
			.clientSecret("clientSecret")
			.build();
	// @formatter:on

	// @formatter:off
	private static final ClientRegistration GITHUB_CLIENT_REGISTRATION = CommonOAuth2Provider.GITHUB
			.getBuilder("github")
			.clientId("clientId")
			.clientSecret("clientSecret")
			.build();
	// @formatter:on

	private static final String SUBJECT = "surfer-dude";

	private static final String ACCESS_TOKEN_VALUE = "hang-ten";

	private static final String REFRESH_TOKEN_VALUE = "surfs-up";

	private static final String ID_TOKEN_VALUE = "beach-break";

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	private SecurityContextRepository securityContextRepository;

	@Autowired
	private OAuth2AuthorizedClientRepository authorizedClientRepository;

	@Autowired
	private OAuth2AccessTokenResponseClient<OAuth2RefreshTokenGrantRequest> refreshTokenAccessTokenResponseClient;

	@Autowired
	private JwtDecoder jwtDecoder;

	@Autowired
	private OidcUserService oidcUserService;

	@Autowired
	private OAuth2AuthorizedClientManager authorizedClientManager;

	private MockHttpServletRequest request;

	private MockHttpServletResponse response;

	@BeforeEach
	public void setUp() {
		this.request = new MockHttpServletRequest("GET", "");
		this.request.setServletPath("/");
		this.response = new MockHttpServletResponse();
		RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(this.request, this.response));
	}

	@AfterEach
	public void cleanUp() {
		SecurityContextHolder.clearContext();
		RequestContextHolder.resetRequestAttributes();
	}

	@Test
	public void authorizeWhenAccessTokenResponseMissingOpenidScopeThenOidcUserNotRefreshed() {
		this.spring.register(OAuth2LoginWithOAuth2ClientConfig.class).autowire();

		OAuth2AuthorizedClient authorizedClient = createAuthorizedClient();
		OAuth2AccessTokenResponse accessTokenResponse = createAccessTokenResponse();
		given(this.authorizedClientRepository.loadAuthorizedClient(anyString(), any(Authentication.class),
				any(HttpServletRequest.class)))
			.willReturn(authorizedClient);
		given(this.refreshTokenAccessTokenResponseClient.getTokenResponse(any(OAuth2RefreshTokenGrantRequest.class)))
			.willReturn(accessTokenResponse);

		OAuth2AuthenticationToken authentication = createAuthenticationToken(GOOGLE_CLIENT_REGISTRATION);
		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
			.withClientRegistrationId(GOOGLE_CLIENT_REGISTRATION.getRegistrationId())
			.principal(authentication)
			.build();
		OAuth2AuthorizedClient refreshedAuthorizedClient = this.authorizedClientManager.authorize(authorizeRequest);
		assertThat(refreshedAuthorizedClient).isNotNull();
		verifyNoInteractions(this.securityContextRepository, this.jwtDecoder, this.oidcUserService);
	}

	@Test
	public void authorizeWhenAccessTokenResponseMissingIdTokenThenOidcUserNotRefreshed() {
		this.spring.register(OAuth2LoginWithOAuth2ClientConfig.class).autowire();

		OAuth2AuthorizedClient authorizedClient = createAuthorizedClient();
		OAuth2AccessTokenResponse accessTokenResponse = TestOAuth2AccessTokenResponses.oidcAccessTokenResponse()
			.build();
		given(this.authorizedClientRepository.loadAuthorizedClient(anyString(), any(Authentication.class),
				any(HttpServletRequest.class)))
			.willReturn(authorizedClient);
		given(this.refreshTokenAccessTokenResponseClient.getTokenResponse(any(OAuth2RefreshTokenGrantRequest.class)))
			.willReturn(accessTokenResponse);

		OAuth2AuthenticationToken authentication = createAuthenticationToken(GOOGLE_CLIENT_REGISTRATION);
		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
			.withClientRegistrationId(GOOGLE_CLIENT_REGISTRATION.getRegistrationId())
			.principal(authentication)
			.build();
		OAuth2AuthorizedClient refreshedAuthorizedClient = this.authorizedClientManager.authorize(authorizeRequest);
		assertThat(refreshedAuthorizedClient).isNotNull();
		verifyNoInteractions(this.securityContextRepository, this.jwtDecoder, this.oidcUserService);
	}

	@Test
	public void authorizeWhenAuthenticationIsNotOAuth2ThenOidcUserNotRefreshed() {
		this.spring.register(OAuth2LoginWithOAuth2ClientConfig.class).autowire();

		OAuth2AuthorizedClient authorizedClient = createAuthorizedClient();
		OAuth2AccessTokenResponse accessTokenResponse = createAccessTokenResponse(OidcScopes.OPENID);
		given(this.authorizedClientRepository.loadAuthorizedClient(anyString(), any(Authentication.class),
				any(HttpServletRequest.class)))
			.willReturn(authorizedClient);
		given(this.refreshTokenAccessTokenResponseClient.getTokenResponse(any(OAuth2RefreshTokenGrantRequest.class)))
			.willReturn(accessTokenResponse);

		TestingAuthenticationToken authentication = new TestingAuthenticationToken(SUBJECT, null);
		SecurityContextImpl securityContext = new SecurityContextImpl(authentication);
		SecurityContextHolder.setContext(securityContext);

		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
			.withClientRegistrationId(GOOGLE_CLIENT_REGISTRATION.getRegistrationId())
			.principal(authentication)
			.build();
		OAuth2AuthorizedClient refreshedAuthorizedClient = this.authorizedClientManager.authorize(authorizeRequest);
		assertThat(refreshedAuthorizedClient).isNotNull();
		verifyNoInteractions(this.securityContextRepository, this.jwtDecoder, this.oidcUserService);
	}

	@Test
	public void authorizeWhenAuthenticationIsCustomThenOidcUserNotRefreshed() {
		this.spring.register(OAuth2LoginWithOAuth2ClientConfig.class).autowire();

		OAuth2AuthorizedClient authorizedClient = createAuthorizedClient();
		OAuth2AccessTokenResponse accessTokenResponse = createAccessTokenResponse(OidcScopes.OPENID);
		given(this.authorizedClientRepository.loadAuthorizedClient(anyString(), any(Authentication.class),
				any(HttpServletRequest.class)))
			.willReturn(authorizedClient);
		given(this.refreshTokenAccessTokenResponseClient.getTokenResponse(any(OAuth2RefreshTokenGrantRequest.class)))
			.willReturn(accessTokenResponse);

		OidcUser oidcUser = createOidcUser();
		OAuth2AuthenticationToken authentication = new CustomOAuth2AuthenticationToken(oidcUser,
				oidcUser.getAuthorities(), GOOGLE_CLIENT_REGISTRATION.getRegistrationId());
		SecurityContextImpl securityContext = new SecurityContextImpl(authentication);
		SecurityContextHolder.setContext(securityContext);

		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
			.withClientRegistrationId(GOOGLE_CLIENT_REGISTRATION.getRegistrationId())
			.principal(authentication)
			.build();
		OAuth2AuthorizedClient refreshedAuthorizedClient = this.authorizedClientManager.authorize(authorizeRequest);
		assertThat(refreshedAuthorizedClient).isNotNull();
		verifyNoInteractions(this.securityContextRepository, this.jwtDecoder, this.oidcUserService);
	}

	@Test
	public void authorizeWhenPrincipalIsOAuth2UserThenOidcUserNotRefreshed() {
		this.spring.register(OAuth2LoginWithOAuth2ClientConfig.class).autowire();

		OAuth2AuthorizedClient authorizedClient = createAuthorizedClient();
		OAuth2AccessTokenResponse accessTokenResponse = createAccessTokenResponse(OidcScopes.OPENID);
		given(this.authorizedClientRepository.loadAuthorizedClient(anyString(), any(Authentication.class),
				any(HttpServletRequest.class)))
			.willReturn(authorizedClient);
		given(this.refreshTokenAccessTokenResponseClient.getTokenResponse(any(OAuth2RefreshTokenGrantRequest.class)))
			.willReturn(accessTokenResponse);

		Map<String, Object> attributes = Map.of(StandardClaimNames.SUB, SUBJECT);
		OAuth2User oauth2User = new DefaultOAuth2User(AuthorityUtils.createAuthorityList("OAUTH2_USER"), attributes,
				StandardClaimNames.SUB);
		OAuth2AuthenticationToken authentication = new OAuth2AuthenticationToken(oauth2User,
				oauth2User.getAuthorities(), GOOGLE_CLIENT_REGISTRATION.getRegistrationId());
		SecurityContextImpl securityContext = new SecurityContextImpl(authentication);
		SecurityContextHolder.setContext(securityContext);

		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
			.withClientRegistrationId(GOOGLE_CLIENT_REGISTRATION.getRegistrationId())
			.principal(authentication)
			.build();
		OAuth2AuthorizedClient refreshedAuthorizedClient = this.authorizedClientManager.authorize(authorizeRequest);
		assertThat(refreshedAuthorizedClient).isNotNull();
		verifyNoInteractions(this.securityContextRepository, this.jwtDecoder, this.oidcUserService);
	}

	@Test
	public void authorizeWhenAuthenticationClientRegistrationIdDoesNotMatchThenOidcUserNotRefreshed() {
		this.spring.register(OAuth2LoginWithOAuth2ClientConfig.class).autowire();

		OAuth2AuthorizedClient authorizedClient = createAuthorizedClient();
		OAuth2AccessTokenResponse accessTokenResponse = createAccessTokenResponse(OidcScopes.OPENID);
		given(this.authorizedClientRepository.loadAuthorizedClient(anyString(), any(Authentication.class),
				any(HttpServletRequest.class)))
			.willReturn(authorizedClient);
		given(this.refreshTokenAccessTokenResponseClient.getTokenResponse(any(OAuth2RefreshTokenGrantRequest.class)))
			.willReturn(accessTokenResponse);

		OAuth2AuthenticationToken authentication = createAuthenticationToken(GITHUB_CLIENT_REGISTRATION);
		SecurityContextImpl securityContext = new SecurityContextImpl(authentication);
		SecurityContextHolder.setContext(securityContext);

		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
			.withClientRegistrationId(GOOGLE_CLIENT_REGISTRATION.getRegistrationId())
			.principal(authentication)
			.build();
		OAuth2AuthorizedClient refreshedAuthorizedClient = this.authorizedClientManager.authorize(authorizeRequest);
		assertThat(refreshedAuthorizedClient).isNotNull();
		verifyNoInteractions(this.securityContextRepository, this.jwtDecoder, this.oidcUserService);
	}

	@Test
	public void authorizeWhenAccessTokenResponseIncludesIdTokenThenOidcUserRefreshed() {
		this.spring.register(OAuth2LoginWithOAuth2ClientConfig.class).autowire();

		OAuth2AuthorizedClient authorizedClient = createAuthorizedClient();
		OAuth2AccessTokenResponse accessTokenResponse = createAccessTokenResponse(OidcScopes.OPENID);
		Jwt jwt = createJwt();
		OidcUser oidcUser = createOidcUser();
		given(this.authorizedClientRepository.loadAuthorizedClient(anyString(), any(Authentication.class),
				any(HttpServletRequest.class)))
			.willReturn(authorizedClient);
		given(this.refreshTokenAccessTokenResponseClient.getTokenResponse(any(OAuth2RefreshTokenGrantRequest.class)))
			.willReturn(accessTokenResponse);
		given(this.jwtDecoder.decode(anyString())).willReturn(jwt);
		given(this.oidcUserService.loadUser(any(OidcUserRequest.class))).willReturn(oidcUser);

		OAuth2AuthenticationToken authentication = createAuthenticationToken(GOOGLE_CLIENT_REGISTRATION);
		SecurityContextImpl securityContext = new SecurityContextImpl(authentication);
		SecurityContextHolder.setContext(securityContext);

		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
			.withClientRegistrationId(GOOGLE_CLIENT_REGISTRATION.getRegistrationId())
			.principal(authentication)
			.build();
		OAuth2AuthorizedClient refreshedAuthorizedClient = this.authorizedClientManager.authorize(authorizeRequest);
		assertThat(refreshedAuthorizedClient).isNotNull();
		assertThat(refreshedAuthorizedClient).isNotSameAs(authorizedClient);
		assertThat(refreshedAuthorizedClient.getClientRegistration()).isEqualTo(GOOGLE_CLIENT_REGISTRATION);
		assertThat(refreshedAuthorizedClient.getAccessToken()).isEqualTo(accessTokenResponse.getAccessToken());
		assertThat(refreshedAuthorizedClient.getRefreshToken()).isEqualTo(accessTokenResponse.getRefreshToken());

		ArgumentCaptor<OAuth2RefreshTokenGrantRequest> refreshTokenGrantRequestCaptor = ArgumentCaptor
			.forClass(OAuth2RefreshTokenGrantRequest.class);
		ArgumentCaptor<OidcUserRequest> userRequestCaptor = ArgumentCaptor.forClass(OidcUserRequest.class);
		ArgumentCaptor<SecurityContext> securityContextCaptor = ArgumentCaptor.forClass(SecurityContext.class);
		verify(this.authorizedClientRepository).loadAuthorizedClient(GOOGLE_CLIENT_REGISTRATION.getRegistrationId(),
				authentication, this.request);
		verify(this.authorizedClientRepository).saveAuthorizedClient(refreshedAuthorizedClient, authentication,
				this.request, this.response);
		verify(this.refreshTokenAccessTokenResponseClient).getTokenResponse(refreshTokenGrantRequestCaptor.capture());
		verify(this.jwtDecoder).decode(jwt.getTokenValue());
		verify(this.oidcUserService).loadUser(userRequestCaptor.capture());
		verify(this.securityContextRepository).saveContext(securityContextCaptor.capture(), eq(this.request),
				eq(this.response));
		verifyNoMoreInteractions(this.authorizedClientRepository, this.jwtDecoder, this.oidcUserService,
				this.securityContextRepository);

		OAuth2RefreshTokenGrantRequest refreshTokenGrantRequest = refreshTokenGrantRequestCaptor.getValue();
		assertThat(refreshTokenGrantRequest.getClientRegistration())
			.isEqualTo(authorizedClient.getClientRegistration());
		assertThat(refreshTokenGrantRequest.getRefreshToken()).isEqualTo(authorizedClient.getRefreshToken());
		assertThat(refreshTokenGrantRequest.getAccessToken()).isEqualTo(authorizedClient.getAccessToken());

		OidcUserRequest userRequest = userRequestCaptor.getValue();
		assertThat(userRequest.getClientRegistration()).isEqualTo(GOOGLE_CLIENT_REGISTRATION);
		assertThat(userRequest.getAccessToken()).isEqualTo(accessTokenResponse.getAccessToken());
		assertThat(userRequest.getIdToken().getTokenValue()).isEqualTo(jwt.getTokenValue());

		SecurityContext refreshedSecurityContext = securityContextCaptor.getValue();
		assertThat(refreshedSecurityContext).isNotNull();
		assertThat(refreshedSecurityContext).isNotSameAs(securityContext);
		assertThat(refreshedSecurityContext).isSameAs(SecurityContextHolder.getContext());
		assertThat(refreshedSecurityContext.getAuthentication()).isInstanceOf(OAuth2AuthenticationToken.class);
		assertThat(refreshedSecurityContext.getAuthentication()).isNotSameAs(authentication);
		assertThat(refreshedSecurityContext.getAuthentication().getPrincipal()).isInstanceOf(OidcUser.class);
		assertThat(refreshedSecurityContext.getAuthentication().getPrincipal())
			.isNotSameAs(authentication.getPrincipal());
	}

	private OAuth2AuthorizedClient createAuthorizedClient() {
		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plus(30, ChronoUnit.SECONDS);
		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, ACCESS_TOKEN_VALUE,
				issuedAt, expiresAt, Set.of(OidcScopes.OPENID));
		OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(REFRESH_TOKEN_VALUE, issuedAt);

		return new OAuth2AuthorizedClient(GOOGLE_CLIENT_REGISTRATION, SUBJECT, accessToken, refreshToken);
	}

	private OAuth2AccessTokenResponse createAccessTokenResponse(String... scope) {
		Set<String> scopes = Set.of(scope);
		Map<String, Object> additionalParameters = new HashMap<>();
		if (scopes.contains(OidcScopes.OPENID)) {
			additionalParameters.put(OidcParameterNames.ID_TOKEN, ID_TOKEN_VALUE);
		}

		return OAuth2AccessTokenResponse.withToken(ACCESS_TOKEN_VALUE)
			.tokenType(OAuth2AccessToken.TokenType.BEARER)
			.scopes(scopes)
			.refreshToken(REFRESH_TOKEN_VALUE)
			.expiresIn(60L)
			.additionalParameters(additionalParameters)
			.build();
	}

	private Jwt createJwt() {
		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plus(1, ChronoUnit.MINUTES);
		return TestJwts.jwt()
			.subject(SUBJECT)
			.tokenValue(ID_TOKEN_VALUE)
			.issuedAt(issuedAt)
			.expiresAt(expiresAt)
			.build();
	}

	private OidcUser createOidcUser() {
		Map<String, Object> claims = new HashMap<>();
		claims.put(IdTokenClaimNames.SUB, SUBJECT);
		claims.put(IdTokenClaimNames.ISS, "issuer");
		claims.put(IdTokenClaimNames.AUD, List.of("audience1", "audience2"));
		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plus(1, ChronoUnit.MINUTES);
		OidcIdToken idToken = new OidcIdToken(ID_TOKEN_VALUE, issuedAt, expiresAt, claims);

		return new DefaultOidcUser(AuthorityUtils.createAuthorityList("OIDC_USER"), idToken);
	}

	private OAuth2AuthenticationToken createAuthenticationToken(ClientRegistration clientRegistration) {
		OidcUser oidcUser = createOidcUser();
		return new OAuth2AuthenticationToken(oidcUser, oidcUser.getAuthorities(),
				clientRegistration.getRegistrationId());
	}

	@Configuration
	@EnableWebSecurity
	static class OAuth2LoginWithOAuth2ClientConfig {

		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeHttpRequests((authorize) -> authorize
					.anyRequest().authenticated()
				)
				.securityContext((securityContext) -> securityContext
					.securityContextRepository(this.securityContextRepository())
				)
				.oauth2Login(Customizer.withDefaults())
				.oauth2Client(Customizer.withDefaults());
			// @formatter:on
			return http.build();
		}

		@Bean
		SecurityContextRepository securityContextRepository() {
			return mock(SecurityContextRepository.class);
		}

		@Bean
		ClientRegistrationRepository clientRegistrationRepository() {
			return mock(ClientRegistrationRepository.class);
		}

		@Bean
		OAuth2AuthorizedClientRepository authorizedClientRepository() {
			return mock(OAuth2AuthorizedClientRepository.class);
		}

		@Bean
		@SuppressWarnings("unchecked")
		OAuth2AccessTokenResponseClient<OAuth2RefreshTokenGrantRequest> refreshTokenAccessTokenResponseClient() {
			return mock(OAuth2AccessTokenResponseClient.class);
		}

		@Bean
		JwtDecoder jwtDecoder() {
			return mock(JwtDecoder.class);
		}

		@Bean
		JwtDecoderFactory<ClientRegistration> jwtDecoderFactory() {
			return (clientRegistration) -> jwtDecoder();
		}

		@Bean
		OidcUserService oidcUserService() {
			return mock(OidcUserService.class);
		}

	}

	private static final class CustomOAuth2AuthenticationToken extends OAuth2AuthenticationToken {

		CustomOAuth2AuthenticationToken(OAuth2User principal, Collection<? extends GrantedAuthority> authorities,
				String authorizedClientRegistrationId) {
			super(principal, authorities, authorizedClientRegistrationId);
		}

	}

}
