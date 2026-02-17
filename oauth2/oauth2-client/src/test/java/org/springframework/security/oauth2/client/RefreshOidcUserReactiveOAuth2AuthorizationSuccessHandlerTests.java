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

package org.springframework.security.oauth2.client;

import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.client.userinfo.ReactiveOAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.oidc.user.TestOidcUsers;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoderFactory;
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository;
import org.springframework.web.server.ServerWebExchange;

import static org.assertj.core.api.Assertions.assertThatException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link RefreshOidcUserReactiveOAuth2AuthorizationSuccessHandler}.
 *
 * @author Evgeniy Cheban
 */
class RefreshOidcUserReactiveOAuth2AuthorizationSuccessHandlerTests {

	@Test
	void setServerSecurityContextRepositoryWhenNullThenException() {
		assertThatException()
			.isThrownBy(() -> new RefreshOidcUserReactiveOAuth2AuthorizationSuccessHandler()
				.setServerSecurityContextRepository(null))
			.withMessage("serverSecurityContextRepository cannot be null");
	}

	@Test
	void setJwtDecoderFactoryWhenNullThenException() {
		assertThatException()
			.isThrownBy(() -> new RefreshOidcUserReactiveOAuth2AuthorizationSuccessHandler().setJwtDecoderFactory(null))
			.withMessage("jwtDecoderFactory cannot be null");
	}

	@Test
	void setAuthoritiesMapperWhenNullThenException() {
		assertThatException()
			.isThrownBy(() -> new RefreshOidcUserReactiveOAuth2AuthorizationSuccessHandler().setAuthoritiesMapper(null))
			.withMessage("authoritiesMapper cannot be null");
	}

	@Test
	void setUserServiceWhenNullThenException() {
		assertThatException()
			.isThrownBy(() -> new RefreshOidcUserReactiveOAuth2AuthorizationSuccessHandler().setUserService(null))
			.withMessage("userService cannot be null");
	}

	@Test
	void setClockSkewWhenNullThenException() {
		assertThatException()
			.isThrownBy(() -> new RefreshOidcUserReactiveOAuth2AuthorizationSuccessHandler().setClockSkew(null))
			.withMessage("clockSkew cannot be null");
	}

	@Test
	void onAuthorizationSuccessWhenIdTokenValidThenSecurityContextRefreshed() {
		ClientRegistration clientRegistration = TestClientRegistrations.clientRegistration().build();
		DefaultOidcUser principal = TestOidcUsers.create();
		OAuth2AuthenticationToken authenticationToken = new OAuth2AuthenticationToken(principal,
				principal.getAuthorities(), clientRegistration.getRegistrationId());
		OAuth2AccessToken accessToken = createAccessToken();
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(clientRegistration, principal.getName(),
				accessToken, null);
		MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/").build());
		Map<String, Object> attributes = Map.of(ServerWebExchange.class.getName(), exchange,
				OidcParameterNames.ID_TOKEN, "id-token-1234");
		Map<String, Object> claims = new HashMap<>();
		claims.put("iss", principal.getIssuer());
		claims.put("sub", principal.getSubject());
		claims.put("aud", principal.getAudience());
		claims.put("nonce", principal.getNonce());
		Jwt jwt = mock(Jwt.class);
		given(jwt.getTokenValue()).willReturn("id-token-1234");
		given(jwt.getIssuedAt()).willReturn(principal.getIssuedAt());
		given(jwt.getClaims()).willReturn(claims);
		ReactiveJwtDecoder jwtDecoder = mock(ReactiveJwtDecoder.class);
		given(jwtDecoder.decode(any())).willReturn(Mono.just(jwt));
		ReactiveJwtDecoderFactory<ClientRegistration> reactiveJwtDecoderFactory = mock(ReactiveJwtDecoderFactory.class);
		given(reactiveJwtDecoderFactory.createDecoder(any())).willReturn(jwtDecoder);
		ReactiveOAuth2UserService<OidcUserRequest, OidcUser> userService = mock(ReactiveOAuth2UserService.class);
		given(userService.loadUser(any())).willReturn(Mono.just(principal));
		WebSessionServerSecurityContextRepository serverSecurityContextRepository = new WebSessionServerSecurityContextRepository();
		RefreshOidcUserReactiveOAuth2AuthorizationSuccessHandler handler = new RefreshOidcUserReactiveOAuth2AuthorizationSuccessHandler();
		handler.setJwtDecoderFactory(reactiveJwtDecoderFactory);
		handler.setUserService(userService);
		handler.setServerSecurityContextRepository(serverSecurityContextRepository);
		StepVerifier.create(handler.onAuthorizationSuccess(authorizedClient, authenticationToken, attributes))
			.verifyComplete();
		StepVerifier.create(serverSecurityContextRepository.load(exchange).map(SecurityContext::getAuthentication))
			.expectNext(authenticationToken)
			.verifyComplete();
	}

	@Test
	void onAuthorizationSuccessWhenIdTokenIssuerNotSameThenException() {
		ClientRegistration clientRegistration = TestClientRegistrations.clientRegistration().build();
		DefaultOidcUser principal = TestOidcUsers.create();
		OAuth2AuthenticationToken authenticationToken = new OAuth2AuthenticationToken(principal,
				principal.getAuthorities(), clientRegistration.getRegistrationId());
		OAuth2AccessToken accessToken = createAccessToken();
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(clientRegistration, principal.getName(),
				accessToken, null);
		MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/").build());
		Map<String, Object> attributes = Map.of(ServerWebExchange.class.getName(), exchange,
				OidcParameterNames.ID_TOKEN, "id-token-1234");
		Map<String, Object> claims = new HashMap<>();
		claims.put("iss", "https://issuer.com");
		claims.put("sub", principal.getSubject());
		claims.put("aud", principal.getAudience());
		claims.put("nonce", principal.getNonce());
		Jwt jwt = mock(Jwt.class);
		given(jwt.getTokenValue()).willReturn("id-token-1234");
		given(jwt.getIssuedAt()).willReturn(principal.getIssuedAt());
		given(jwt.getClaims()).willReturn(claims);
		ReactiveJwtDecoder jwtDecoder = mock(ReactiveJwtDecoder.class);
		given(jwtDecoder.decode(any())).willReturn(Mono.just(jwt));
		ReactiveJwtDecoderFactory<ClientRegistration> reactiveJwtDecoderFactory = mock(ReactiveJwtDecoderFactory.class);
		given(reactiveJwtDecoderFactory.createDecoder(any())).willReturn(jwtDecoder);
		ReactiveOAuth2UserService<OidcUserRequest, OidcUser> userService = mock(ReactiveOAuth2UserService.class);
		given(userService.loadUser(any())).willReturn(Mono.just(principal));
		WebSessionServerSecurityContextRepository serverSecurityContextRepository = new WebSessionServerSecurityContextRepository();
		RefreshOidcUserReactiveOAuth2AuthorizationSuccessHandler handler = new RefreshOidcUserReactiveOAuth2AuthorizationSuccessHandler();
		handler.setJwtDecoderFactory(reactiveJwtDecoderFactory);
		handler.setUserService(userService);
		handler.setServerSecurityContextRepository(serverSecurityContextRepository);
		StepVerifier.create(handler.onAuthorizationSuccess(authorizedClient, authenticationToken, attributes))
			.verifyErrorMessage("[invalid_id_token] Invalid issuer");
	}

	@Test
	void onAuthorizationSuccessWhenIdTokenSubNotSameThenException() {
		ClientRegistration clientRegistration = TestClientRegistrations.clientRegistration().build();
		DefaultOidcUser principal = TestOidcUsers.create();
		OAuth2AuthenticationToken authenticationToken = new OAuth2AuthenticationToken(principal,
				principal.getAuthorities(), clientRegistration.getRegistrationId());
		OAuth2AccessToken accessToken = createAccessToken();
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(clientRegistration, principal.getName(),
				accessToken, null);
		MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/").build());
		Map<String, Object> attributes = Map.of(ServerWebExchange.class.getName(), exchange,
				OidcParameterNames.ID_TOKEN, "id-token-1234");
		Map<String, Object> claims = new HashMap<>();
		claims.put("iss", principal.getIssuer());
		claims.put("sub", "invalid_sub");
		claims.put("aud", principal.getAudience());
		claims.put("nonce", principal.getNonce());
		Jwt jwt = mock(Jwt.class);
		given(jwt.getTokenValue()).willReturn("id-token-1234");
		given(jwt.getIssuedAt()).willReturn(principal.getIssuedAt());
		given(jwt.getClaims()).willReturn(claims);
		ReactiveJwtDecoder jwtDecoder = mock(ReactiveJwtDecoder.class);
		given(jwtDecoder.decode(any())).willReturn(Mono.just(jwt));
		ReactiveJwtDecoderFactory<ClientRegistration> reactiveJwtDecoderFactory = mock(ReactiveJwtDecoderFactory.class);
		given(reactiveJwtDecoderFactory.createDecoder(any())).willReturn(jwtDecoder);
		ReactiveOAuth2UserService<OidcUserRequest, OidcUser> userService = mock(ReactiveOAuth2UserService.class);
		given(userService.loadUser(any())).willReturn(Mono.just(principal));
		WebSessionServerSecurityContextRepository serverSecurityContextRepository = new WebSessionServerSecurityContextRepository();
		RefreshOidcUserReactiveOAuth2AuthorizationSuccessHandler handler = new RefreshOidcUserReactiveOAuth2AuthorizationSuccessHandler();
		handler.setJwtDecoderFactory(reactiveJwtDecoderFactory);
		handler.setUserService(userService);
		handler.setServerSecurityContextRepository(serverSecurityContextRepository);
		StepVerifier.create(handler.onAuthorizationSuccess(authorizedClient, authenticationToken, attributes))
			.verifyErrorMessage("[invalid_id_token] Invalid subject");
	}

	@Test
	void onAuthorizationSuccessWhenIdTokenIatNotAfterThenException() {
		ClientRegistration clientRegistration = TestClientRegistrations.clientRegistration().build();
		DefaultOidcUser principal = TestOidcUsers.create();
		OAuth2AuthenticationToken authenticationToken = new OAuth2AuthenticationToken(principal,
				principal.getAuthorities(), clientRegistration.getRegistrationId());
		OAuth2AccessToken accessToken = createAccessToken();
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(clientRegistration, principal.getName(),
				accessToken, null);
		MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/").build());
		Map<String, Object> attributes = Map.of(ServerWebExchange.class.getName(), exchange,
				OidcParameterNames.ID_TOKEN, "id-token-1234");
		Map<String, Object> claims = new HashMap<>();
		claims.put("iss", principal.getIssuer());
		claims.put("sub", principal.getSubject());
		claims.put("aud", principal.getAudience());
		claims.put("nonce", principal.getNonce());
		Jwt jwt = mock(Jwt.class);
		given(jwt.getTokenValue()).willReturn("id-token-1234");
		given(jwt.getIssuedAt()).willReturn(principal.getIssuedAt().minus(Duration.ofDays(1)));
		given(jwt.getClaims()).willReturn(claims);
		ReactiveJwtDecoder jwtDecoder = mock(ReactiveJwtDecoder.class);
		given(jwtDecoder.decode(any())).willReturn(Mono.just(jwt));
		ReactiveJwtDecoderFactory<ClientRegistration> reactiveJwtDecoderFactory = mock(ReactiveJwtDecoderFactory.class);
		given(reactiveJwtDecoderFactory.createDecoder(any())).willReturn(jwtDecoder);
		ReactiveOAuth2UserService<OidcUserRequest, OidcUser> userService = mock(ReactiveOAuth2UserService.class);
		given(userService.loadUser(any())).willReturn(Mono.just(principal));
		WebSessionServerSecurityContextRepository serverSecurityContextRepository = new WebSessionServerSecurityContextRepository();
		RefreshOidcUserReactiveOAuth2AuthorizationSuccessHandler handler = new RefreshOidcUserReactiveOAuth2AuthorizationSuccessHandler();
		handler.setJwtDecoderFactory(reactiveJwtDecoderFactory);
		handler.setUserService(userService);
		handler.setServerSecurityContextRepository(serverSecurityContextRepository);
		StepVerifier.create(handler.onAuthorizationSuccess(authorizedClient, authenticationToken, attributes))
			.verifyErrorMessage("[invalid_id_token] Invalid issued at time");
	}

	@Test
	void onAuthorizationSuccessWhenIdTokenAudEmptyThenException() {
		ClientRegistration clientRegistration = TestClientRegistrations.clientRegistration().build();
		DefaultOidcUser principal = TestOidcUsers.create();
		OAuth2AuthenticationToken authenticationToken = new OAuth2AuthenticationToken(principal,
				principal.getAuthorities(), clientRegistration.getRegistrationId());
		OAuth2AccessToken accessToken = createAccessToken();
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(clientRegistration, principal.getName(),
				accessToken, null);
		MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/").build());
		Map<String, Object> attributes = Map.of(ServerWebExchange.class.getName(), exchange,
				OidcParameterNames.ID_TOKEN, "id-token-1234");
		Map<String, Object> claims = new HashMap<>();
		claims.put("iss", principal.getIssuer());
		claims.put("sub", principal.getSubject());
		claims.put("aud", Collections.emptyList());
		claims.put("nonce", principal.getNonce());
		Jwt jwt = mock(Jwt.class);
		given(jwt.getTokenValue()).willReturn("id-token-1234");
		given(jwt.getIssuedAt()).willReturn(principal.getIssuedAt());
		given(jwt.getClaims()).willReturn(claims);
		ReactiveJwtDecoder jwtDecoder = mock(ReactiveJwtDecoder.class);
		given(jwtDecoder.decode(any())).willReturn(Mono.just(jwt));
		ReactiveJwtDecoderFactory<ClientRegistration> reactiveJwtDecoderFactory = mock(ReactiveJwtDecoderFactory.class);
		given(reactiveJwtDecoderFactory.createDecoder(any())).willReturn(jwtDecoder);
		ReactiveOAuth2UserService<OidcUserRequest, OidcUser> userService = mock(ReactiveOAuth2UserService.class);
		given(userService.loadUser(any())).willReturn(Mono.just(principal));
		WebSessionServerSecurityContextRepository serverSecurityContextRepository = new WebSessionServerSecurityContextRepository();
		RefreshOidcUserReactiveOAuth2AuthorizationSuccessHandler handler = new RefreshOidcUserReactiveOAuth2AuthorizationSuccessHandler();
		handler.setJwtDecoderFactory(reactiveJwtDecoderFactory);
		handler.setUserService(userService);
		handler.setServerSecurityContextRepository(serverSecurityContextRepository);
		StepVerifier.create(handler.onAuthorizationSuccess(authorizedClient, authenticationToken, attributes))
			.verifyErrorMessage("[invalid_id_token] Invalid audience");
	}

	@Test
	void onAuthorizationSuccessWhenIdTokenAudNotContainThenException() {
		ClientRegistration clientRegistration = TestClientRegistrations.clientRegistration().build();
		DefaultOidcUser principal = TestOidcUsers.create();
		OAuth2AuthenticationToken authenticationToken = new OAuth2AuthenticationToken(principal,
				principal.getAuthorities(), clientRegistration.getRegistrationId());
		OAuth2AccessToken accessToken = createAccessToken();
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(clientRegistration, principal.getName(),
				accessToken, null);
		MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/").build());
		Map<String, Object> attributes = Map.of(ServerWebExchange.class.getName(), exchange,
				OidcParameterNames.ID_TOKEN, "id-token-1234");
		Map<String, Object> claims = new HashMap<>();
		claims.put("iss", principal.getIssuer());
		claims.put("sub", principal.getSubject());
		claims.put("aud", List.of("invalid_client-id"));
		claims.put("nonce", principal.getNonce());
		Jwt jwt = mock(Jwt.class);
		given(jwt.getTokenValue()).willReturn("id-token-1234");
		given(jwt.getIssuedAt()).willReturn(principal.getIssuedAt());
		given(jwt.getClaims()).willReturn(claims);
		ReactiveJwtDecoder jwtDecoder = mock(ReactiveJwtDecoder.class);
		given(jwtDecoder.decode(any())).willReturn(Mono.just(jwt));
		ReactiveJwtDecoderFactory<ClientRegistration> reactiveJwtDecoderFactory = mock(ReactiveJwtDecoderFactory.class);
		given(reactiveJwtDecoderFactory.createDecoder(any())).willReturn(jwtDecoder);
		ReactiveOAuth2UserService<OidcUserRequest, OidcUser> userService = mock(ReactiveOAuth2UserService.class);
		given(userService.loadUser(any())).willReturn(Mono.just(principal));
		WebSessionServerSecurityContextRepository serverSecurityContextRepository = new WebSessionServerSecurityContextRepository();
		RefreshOidcUserReactiveOAuth2AuthorizationSuccessHandler handler = new RefreshOidcUserReactiveOAuth2AuthorizationSuccessHandler();
		handler.setJwtDecoderFactory(reactiveJwtDecoderFactory);
		handler.setUserService(userService);
		handler.setServerSecurityContextRepository(serverSecurityContextRepository);
		StepVerifier.create(handler.onAuthorizationSuccess(authorizedClient, authenticationToken, attributes))
			.verifyErrorMessage("[invalid_id_token] Invalid audience");
	}

	@Test
	void onAuthorizationSuccessWhenIdTokenAuthTimeNotSameThenException() {
		ClientRegistration clientRegistration = TestClientRegistrations.clientRegistration().build();
		DefaultOidcUser principal = TestOidcUsers.create();
		OAuth2AuthenticationToken authenticationToken = new OAuth2AuthenticationToken(principal,
				principal.getAuthorities(), clientRegistration.getRegistrationId());
		OAuth2AccessToken accessToken = createAccessToken();
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(clientRegistration, principal.getName(),
				accessToken, null);
		MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/").build());
		Map<String, Object> attributes = Map.of(ServerWebExchange.class.getName(), exchange,
				OidcParameterNames.ID_TOKEN, "id-token-1234");
		Map<String, Object> claims = new HashMap<>();
		claims.put("iss", principal.getIssuer());
		claims.put("sub", principal.getSubject());
		claims.put("aud", principal.getAudience());
		claims.put("auth_time", principal.getIssuedAt());
		claims.put("nonce", principal.getNonce());
		Jwt jwt = mock(Jwt.class);
		given(jwt.getTokenValue()).willReturn("id-token-1234");
		given(jwt.getIssuedAt()).willReturn(principal.getIssuedAt());
		given(jwt.getClaims()).willReturn(claims);
		ReactiveJwtDecoder jwtDecoder = mock(ReactiveJwtDecoder.class);
		given(jwtDecoder.decode(any())).willReturn(Mono.just(jwt));
		ReactiveJwtDecoderFactory<ClientRegistration> reactiveJwtDecoderFactory = mock(ReactiveJwtDecoderFactory.class);
		given(reactiveJwtDecoderFactory.createDecoder(any())).willReturn(jwtDecoder);
		ReactiveOAuth2UserService<OidcUserRequest, OidcUser> userService = mock(ReactiveOAuth2UserService.class);
		given(userService.loadUser(any())).willReturn(Mono.just(principal));
		WebSessionServerSecurityContextRepository serverSecurityContextRepository = new WebSessionServerSecurityContextRepository();
		RefreshOidcUserReactiveOAuth2AuthorizationSuccessHandler handler = new RefreshOidcUserReactiveOAuth2AuthorizationSuccessHandler();
		handler.setJwtDecoderFactory(reactiveJwtDecoderFactory);
		handler.setUserService(userService);
		handler.setServerSecurityContextRepository(serverSecurityContextRepository);
		StepVerifier.create(handler.onAuthorizationSuccess(authorizedClient, authenticationToken, attributes))
			.verifyErrorMessage("[invalid_id_token] Invalid authenticated at time");
	}

	@Test
	void onAuthorizationSuccessWhenIdTokenNonceNotSameThenException() {
		ClientRegistration clientRegistration = TestClientRegistrations.clientRegistration().build();
		DefaultOidcUser principal = TestOidcUsers.create();
		OAuth2AuthenticationToken authenticationToken = new OAuth2AuthenticationToken(principal,
				principal.getAuthorities(), clientRegistration.getRegistrationId());
		OAuth2AccessToken accessToken = createAccessToken();
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(clientRegistration, principal.getName(),
				accessToken, null);
		MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/").build());
		Map<String, Object> attributes = Map.of(ServerWebExchange.class.getName(), exchange,
				OidcParameterNames.ID_TOKEN, "id-token-1234");
		Map<String, Object> claims = new HashMap<>();
		claims.put("iss", principal.getIssuer());
		claims.put("sub", principal.getSubject());
		claims.put("aud", principal.getAudience());
		claims.put("nonce", "invalid_nonce");
		Jwt jwt = mock(Jwt.class);
		given(jwt.getTokenValue()).willReturn("id-token-1234");
		given(jwt.getIssuedAt()).willReturn(principal.getIssuedAt());
		given(jwt.getClaims()).willReturn(claims);
		ReactiveJwtDecoder jwtDecoder = mock(ReactiveJwtDecoder.class);
		given(jwtDecoder.decode(any())).willReturn(Mono.just(jwt));
		ReactiveJwtDecoderFactory<ClientRegistration> reactiveJwtDecoderFactory = mock(ReactiveJwtDecoderFactory.class);
		given(reactiveJwtDecoderFactory.createDecoder(any())).willReturn(jwtDecoder);
		ReactiveOAuth2UserService<OidcUserRequest, OidcUser> userService = mock(ReactiveOAuth2UserService.class);
		given(userService.loadUser(any())).willReturn(Mono.just(principal));
		WebSessionServerSecurityContextRepository serverSecurityContextRepository = new WebSessionServerSecurityContextRepository();
		RefreshOidcUserReactiveOAuth2AuthorizationSuccessHandler handler = new RefreshOidcUserReactiveOAuth2AuthorizationSuccessHandler();
		handler.setJwtDecoderFactory(reactiveJwtDecoderFactory);
		handler.setUserService(userService);
		handler.setServerSecurityContextRepository(serverSecurityContextRepository);
		StepVerifier.create(handler.onAuthorizationSuccess(authorizedClient, authenticationToken, attributes))
			.verifyErrorMessage("[invalid_nonce] Invalid nonce");
	}

	private static OAuth2AccessToken createAccessToken() {
		Instant issuedAt = Instant.now().minus(Duration.ofDays(1));
		Instant expiresAt = issuedAt.plus(Duration.ofMinutes(60));
		return new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "access-token-1234", issuedAt, expiresAt,
				Set.of(OidcScopes.OPENID));
	}

}
