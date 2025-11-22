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

package org.springframework.security.oauth2.client.oidc.authentication;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.event.OAuth2AuthorizedClientRefreshedEvent;
import org.springframework.security.oauth2.client.oidc.authentication.event.OidcUserRefreshedEvent;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
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
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.TestJwts;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;

/**
 * Tests for {@link OidcAuthorizedClientRefreshedEventListener}.
 *
 * @author Steve Riesenberg
 */
public class OidcAuthorizedClientRefreshedEventListenerTests {

	private static final String INVALID_ID_TOKEN_ERROR = "invalid_id_token";

	private static final String INVALID_NONCE_ERROR = "invalid_nonce";

	private static final String SUBJECT = "surfer-dude";

	private static final String ACCESS_TOKEN_VALUE = "hang-ten";

	private static final String REFRESH_TOKEN_VALUE = "surfs-up";

	private static final String ID_TOKEN_VALUE = "beach-break";

	private OidcAuthorizedClientRefreshedEventListener eventListener;

	private SecurityContextHolderStrategy securityContextHolderStrategy;

	private JwtDecoder jwtDecoder;

	private OidcUserService userService;

	private ApplicationEventPublisher applicationEventPublisher;

	private ClientRegistration clientRegistration;

	private OAuth2AuthorizedClient authorizedClient;

	private OAuth2AccessTokenResponse accessTokenResponse;

	private Jwt jwt;

	private OidcUser oidcUser;

	private OAuth2AuthenticationToken authentication;

	@BeforeEach
	public void setUp() {
		this.jwtDecoder = mock(JwtDecoder.class);
		this.userService = mock(OidcUserService.class);
		this.securityContextHolderStrategy = mock(SecurityContextHolderStrategy.class);
		this.applicationEventPublisher = mock(ApplicationEventPublisher.class);

		this.eventListener = new OidcAuthorizedClientRefreshedEventListener();
		this.eventListener.setUserService(this.userService);
		this.eventListener.setJwtDecoderFactory((clientRegistration) -> this.jwtDecoder);
		this.eventListener.setSecurityContextHolderStrategy(this.securityContextHolderStrategy);
		this.eventListener.setApplicationEventPublisher(this.applicationEventPublisher);

		this.clientRegistration = TestClientRegistrations.clientRegistration().scope(OidcScopes.OPENID).build();
		this.authorizedClient = createAuthorizedClient(this.clientRegistration);
		this.accessTokenResponse = createAccessTokenResponse(OidcScopes.OPENID);
		this.jwt = createJwt().build();
		this.oidcUser = createOidcUser();
		this.authentication = createAuthenticationToken(this.clientRegistration, createOidcUser());
	}

	@Test
	public void setSecurityContextHolderStrategyWhenNullThenThrowsIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
			.isThrownBy(() -> this.eventListener.setSecurityContextHolderStrategy(null))
			.withMessage("securityContextHolderStrategy cannot be null");
		// @formatter:on
	}

	@Test
	public void setJwtDecoderFactoryWhenNullThenThrowsIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
			.isThrownBy(() -> this.eventListener.setJwtDecoderFactory(null))
			.withMessage("jwtDecoderFactory cannot be null");
		// @formatter:on
	}

	@Test
	public void setUserServiceWhenNullThenThrowsIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
			.isThrownBy(() -> this.eventListener.setUserService(null))
			.withMessage("userService cannot be null");
		// @formatter:on
	}

	@Test
	public void setAuthoritiesMapperWhenNullThenThrowsIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
			.isThrownBy(() -> this.eventListener.setAuthoritiesMapper(null))
			.withMessage("authoritiesMapper cannot be null");
		// @formatter:on
	}

	@Test
	public void setApplicationEventPublisherWhenNullThenThrowsIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
			.isThrownBy(() -> this.eventListener.setApplicationEventPublisher(null))
			.withMessage("applicationEventPublisher cannot be null");
		// @formatter:on
	}

	@Test
	public void setClockSkewWhenNullThenThrowsIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
			.isThrownBy(() -> this.eventListener.setClockSkew(null))
			.withMessage("clockSkew cannot be null");
		// @formatter:on
	}

	@Test
	public void setClockSkewWhenNegativeThenThrowsIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
			.isThrownBy(() -> this.eventListener.setClockSkew(Duration.ofMillis(-1)))
			.withMessage("clockSkew must be >= 0");
		// @formatter:on
	}

	@Test
	public void onApplicationEventWhenAccessTokenResponseMissingIdTokenThenOidcUserRefreshedEventNotPublished() {
		OAuth2AccessTokenResponse accessTokenResponse = TestOAuth2AccessTokenResponses.accessTokenResponse()
			.scopes(Set.of(OidcScopes.OPENID))
			.build();
		OAuth2AuthorizedClientRefreshedEvent authorizedClientRefreshedEvent = new OAuth2AuthorizedClientRefreshedEvent(
				accessTokenResponse, this.authorizedClient);
		this.eventListener.onApplicationEvent(authorizedClientRefreshedEvent);
		verifyNoInteractions(this.securityContextHolderStrategy, this.jwtDecoder, this.userService,
				this.applicationEventPublisher);
	}

	@Test
	public void onApplicationEventWhenAccessTokenResponseMissingOpenidScopeThenOidcUserRefreshedEventNotPublished() {
		OAuth2AccessTokenResponse accessTokenResponse = TestOAuth2AccessTokenResponses.oidcAccessTokenResponse()
			.scopes(Set.of())
			.build();
		OAuth2AuthorizedClientRefreshedEvent authorizedClientRefreshedEvent = new OAuth2AuthorizedClientRefreshedEvent(
				accessTokenResponse, this.authorizedClient);
		this.eventListener.onApplicationEvent(authorizedClientRefreshedEvent);
		verifyNoInteractions(this.securityContextHolderStrategy, this.jwtDecoder, this.userService,
				this.applicationEventPublisher);
	}

	@Test
	public void onApplicationEventWhenAuthenticationIsNotOAuth2ThenOidcUserRefreshedEventNotPublished() {
		TestingAuthenticationToken authentication = new TestingAuthenticationToken(SUBJECT, null);
		SecurityContextImpl securityContext = new SecurityContextImpl(authentication);
		given(this.securityContextHolderStrategy.getContext()).willReturn(securityContext);

		OAuth2AuthorizedClientRefreshedEvent authorizedClientRefreshedEvent = new OAuth2AuthorizedClientRefreshedEvent(
				this.accessTokenResponse, this.authorizedClient);
		this.eventListener.onApplicationEvent(authorizedClientRefreshedEvent);

		verify(this.securityContextHolderStrategy).getContext();
		verifyNoMoreInteractions(this.securityContextHolderStrategy);
		verifyNoInteractions(this.jwtDecoder, this.userService, this.applicationEventPublisher);
	}

	@Test
	public void onApplicationEventWhenAuthenticationIsSubclassedThenOidcUserRefreshedEventPublished() {
		OAuth2AuthenticationToken authentication = new CustomOAuth2AuthenticationToken(this.oidcUser,
				this.oidcUser.getAuthorities(), this.clientRegistration.getRegistrationId());
		SecurityContextImpl securityContext = new SecurityContextImpl(authentication);
		given(this.securityContextHolderStrategy.getContext()).willReturn(securityContext);
		given(this.jwtDecoder.decode(anyString())).willReturn(this.jwt);
		given(this.userService.loadUser(any(OidcUserRequest.class))).willReturn(this.oidcUser);

		OAuth2AuthorizedClientRefreshedEvent authorizedClientRefreshedEvent = new OAuth2AuthorizedClientRefreshedEvent(
				this.accessTokenResponse, this.authorizedClient);
		this.eventListener.onApplicationEvent(authorizedClientRefreshedEvent);

		verify(this.applicationEventPublisher).publishEvent(any(OidcUserRefreshedEvent.class));
		verifyNoMoreInteractions(this.applicationEventPublisher);
	}

	@Test
	public void onApplicationEventWhenPrincipalIsOAuth2UserThenOidcUserRefreshedEventNotPublished() {
		Map<String, Object> attributes = Map.of(StandardClaimNames.SUB, SUBJECT);
		OAuth2User oauth2User = new DefaultOAuth2User(AuthorityUtils.createAuthorityList("OAUTH2_USER"), attributes,
				StandardClaimNames.SUB);
		OAuth2AuthenticationToken authentication = new OAuth2AuthenticationToken(oauth2User,
				oauth2User.getAuthorities(), this.clientRegistration.getRegistrationId());
		SecurityContextImpl securityContext = new SecurityContextImpl(authentication);
		given(this.securityContextHolderStrategy.getContext()).willReturn(securityContext);

		OAuth2AuthorizedClientRefreshedEvent authorizedClientRefreshedEvent = new OAuth2AuthorizedClientRefreshedEvent(
				this.accessTokenResponse, this.authorizedClient);
		this.eventListener.onApplicationEvent(authorizedClientRefreshedEvent);

		verify(this.securityContextHolderStrategy).getContext();
		verifyNoMoreInteractions(this.securityContextHolderStrategy);
		verifyNoInteractions(this.jwtDecoder, this.userService, this.applicationEventPublisher);
	}

	@Test
	public void onApplicationEventWhenClientRegistrationIdDoesNotMatchThenOidcUserRefreshedEventNotPublished() {
		ClientRegistration clientRegistration = TestClientRegistrations.clientRegistration()
			.registrationId("test")
			.build();
		OAuth2AuthenticationToken authentication = createAuthenticationToken(clientRegistration, this.oidcUser);
		SecurityContextImpl securityContext = new SecurityContextImpl(authentication);
		given(this.securityContextHolderStrategy.getContext()).willReturn(securityContext);

		OAuth2AuthorizedClientRefreshedEvent authorizedClientRefreshedEvent = new OAuth2AuthorizedClientRefreshedEvent(
				this.accessTokenResponse, this.authorizedClient);
		this.eventListener.onApplicationEvent(authorizedClientRefreshedEvent);

		verify(this.securityContextHolderStrategy).getContext();
		verifyNoMoreInteractions(this.securityContextHolderStrategy);
		verifyNoInteractions(this.jwtDecoder, this.userService, this.applicationEventPublisher);
	}

	@Test
	public void onApplicationEventWhenAccessTokenResponseIncludesIdTokenThenOidcUserRefreshedEventPublished() {
		SecurityContextImpl securityContext = new SecurityContextImpl(this.authentication);
		given(this.securityContextHolderStrategy.getContext()).willReturn(securityContext);
		given(this.jwtDecoder.decode(anyString())).willReturn(this.jwt);
		given(this.userService.loadUser(any(OidcUserRequest.class))).willReturn(this.oidcUser);

		OAuth2AuthorizedClientRefreshedEvent authorizedClientRefreshedEvent = new OAuth2AuthorizedClientRefreshedEvent(
				this.accessTokenResponse, this.authorizedClient);
		this.eventListener.onApplicationEvent(authorizedClientRefreshedEvent);

		ArgumentCaptor<OidcUserRequest> userRequestCaptor = ArgumentCaptor.forClass(OidcUserRequest.class);
		ArgumentCaptor<OidcUserRefreshedEvent> userRefreshedEventCaptor = ArgumentCaptor
			.forClass(OidcUserRefreshedEvent.class);
		verify(this.securityContextHolderStrategy).getContext();
		verify(this.jwtDecoder).decode(this.jwt.getTokenValue());
		verify(this.userService).loadUser(userRequestCaptor.capture());
		verify(this.applicationEventPublisher).publishEvent(userRefreshedEventCaptor.capture());
		verifyNoMoreInteractions(this.securityContextHolderStrategy, this.jwtDecoder, this.userService,
				this.applicationEventPublisher);

		OidcUserRequest userRequest = userRequestCaptor.getValue();
		assertThat(userRequest.getClientRegistration()).isSameAs(this.clientRegistration);
		assertThat(userRequest.getAccessToken()).isSameAs(this.accessTokenResponse.getAccessToken());
		assertThat(userRequest.getIdToken().getTokenValue()).isEqualTo(this.jwt.getTokenValue());

		OidcUserRefreshedEvent userRefreshedEvent = userRefreshedEventCaptor.getValue();
		assertThat(userRefreshedEvent.getAccessTokenResponse()).isSameAs(this.accessTokenResponse);
		assertThat(userRefreshedEvent.getOldOidcUser()).isSameAs(this.authentication.getPrincipal());
		assertThat(userRefreshedEvent.getNewOidcUser()).isSameAs(this.oidcUser);
		assertThat(userRefreshedEvent.getOldOidcUser()).isNotSameAs(userRefreshedEvent.getNewOidcUser());
		assertThat(userRefreshedEvent.getAuthentication()).isNotSameAs(this.authentication);
		assertThat(userRefreshedEvent.getAuthentication()).isInstanceOf(OAuth2AuthenticationToken.class);

		OAuth2AuthenticationToken authenticationResult = (OAuth2AuthenticationToken) userRefreshedEvent
			.getAuthentication();
		assertThat(authenticationResult.getPrincipal()).isEqualTo(this.oidcUser);
		assertThat(authenticationResult.getAuthorities()).containsExactlyElementsOf(this.oidcUser.getAuthorities());
		assertThat(authenticationResult.getAuthorizedClientRegistrationId())
			.isEqualTo(this.clientRegistration.getRegistrationId());
	}

	@Test
	public void onApplicationEventWhenIdTokenIssuerDoesNotMatchThenThrowsOAuth2AuthenticationException() {
		Jwt jwt = createJwt().issuer("https://invalid.url").build();
		SecurityContextImpl securityContext = new SecurityContextImpl(this.authentication);
		given(this.securityContextHolderStrategy.getContext()).willReturn(securityContext);
		given(this.jwtDecoder.decode(anyString())).willReturn(jwt);

		OAuth2AuthorizedClientRefreshedEvent authorizedClientRefreshedEvent = new OAuth2AuthorizedClientRefreshedEvent(
				this.accessTokenResponse, this.authorizedClient);
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
			.isThrownBy(() -> this.eventListener.onApplicationEvent(authorizedClientRefreshedEvent))
			.withMessageContaining("Invalid issuer")
			.extracting(OAuth2AuthenticationException::getError)
			.extracting(OAuth2Error::getErrorCode)
			.isEqualTo(INVALID_ID_TOKEN_ERROR);
		verify(this.securityContextHolderStrategy).getContext();
		verify(this.jwtDecoder).decode(this.jwt.getTokenValue());
		verifyNoMoreInteractions(this.securityContextHolderStrategy, this.jwtDecoder);
		verifyNoInteractions(this.userService, this.applicationEventPublisher);
	}

	@Test
	public void onApplicationEventWhenIdTokenSubjectDoesNotMatchThenThrowsOAuth2AuthenticationException() {
		Jwt jwt = createJwt().subject("invalid").build();
		SecurityContextImpl securityContext = new SecurityContextImpl(this.authentication);
		given(this.securityContextHolderStrategy.getContext()).willReturn(securityContext);
		given(this.jwtDecoder.decode(anyString())).willReturn(jwt);

		OAuth2AuthorizedClientRefreshedEvent authorizedClientRefreshedEvent = new OAuth2AuthorizedClientRefreshedEvent(
				this.accessTokenResponse, this.authorizedClient);
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
			.isThrownBy(() -> this.eventListener.onApplicationEvent(authorizedClientRefreshedEvent))
			.withMessageContaining("Invalid subject")
			.extracting(OAuth2AuthenticationException::getError)
			.extracting(OAuth2Error::getErrorCode)
			.isEqualTo(INVALID_ID_TOKEN_ERROR);
		verify(this.securityContextHolderStrategy).getContext();
		verify(this.jwtDecoder).decode(this.jwt.getTokenValue());
		verifyNoMoreInteractions(this.securityContextHolderStrategy, this.jwtDecoder);
		verifyNoInteractions(this.userService, this.applicationEventPublisher);
	}

	@Test
	public void onApplicationEventWhenIdTokenIssuedAtIsBeforeThenThrowsOAuth2AuthenticationException() {
		Instant issuedAt = this.oidcUser.getIssuedAt().minus(2, ChronoUnit.MINUTES);
		Jwt jwt = createJwt().issuedAt(issuedAt).build();
		SecurityContextImpl securityContext = new SecurityContextImpl(this.authentication);
		given(this.securityContextHolderStrategy.getContext()).willReturn(securityContext);
		given(this.jwtDecoder.decode(anyString())).willReturn(jwt);

		OAuth2AuthorizedClientRefreshedEvent authorizedClientRefreshedEvent = new OAuth2AuthorizedClientRefreshedEvent(
				this.accessTokenResponse, this.authorizedClient);
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
			.isThrownBy(() -> this.eventListener.onApplicationEvent(authorizedClientRefreshedEvent))
			.withMessageContaining("Invalid issued at time")
			.extracting(OAuth2AuthenticationException::getError)
			.extracting(OAuth2Error::getErrorCode)
			.isEqualTo(INVALID_ID_TOKEN_ERROR);
		verify(this.securityContextHolderStrategy).getContext();
		verify(this.jwtDecoder).decode(this.jwt.getTokenValue());
		verifyNoMoreInteractions(this.securityContextHolderStrategy, this.jwtDecoder);
		verifyNoInteractions(this.userService, this.applicationEventPublisher);
	}

	@Test
	public void onApplicationEventWhenIdTokenAudienceDoesNotMatchThenThrowsOAuth2AuthenticationException() {
		Jwt jwt = createJwt().audience(List.of("audience1", "audience3")).build();
		SecurityContextImpl securityContext = new SecurityContextImpl(this.authentication);
		given(this.securityContextHolderStrategy.getContext()).willReturn(securityContext);
		given(this.jwtDecoder.decode(anyString())).willReturn(jwt);

		OAuth2AuthorizedClientRefreshedEvent authorizedClientRefreshedEvent = new OAuth2AuthorizedClientRefreshedEvent(
				this.accessTokenResponse, this.authorizedClient);
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
			.isThrownBy(() -> this.eventListener.onApplicationEvent(authorizedClientRefreshedEvent))
			.withMessageContaining("Invalid audience")
			.extracting(OAuth2AuthenticationException::getError)
			.extracting(OAuth2Error::getErrorCode)
			.isEqualTo(INVALID_ID_TOKEN_ERROR);
		verify(this.securityContextHolderStrategy).getContext();
		verify(this.jwtDecoder).decode(this.jwt.getTokenValue());
		verifyNoMoreInteractions(this.securityContextHolderStrategy, this.jwtDecoder);
		verifyNoInteractions(this.userService, this.applicationEventPublisher);
	}

	@Test
	public void onApplicationEventWhenIdTokenAuthenticatedAtDoesNotMatchThenThrowsOAuth2AuthenticationException() {
		Instant authTime = this.oidcUser.getAuthenticatedAt().plus(5, ChronoUnit.SECONDS);
		Jwt jwt = createJwt().claim(IdTokenClaimNames.AUTH_TIME, authTime).build();
		SecurityContextImpl securityContext = new SecurityContextImpl(this.authentication);
		given(this.securityContextHolderStrategy.getContext()).willReturn(securityContext);
		given(this.jwtDecoder.decode(anyString())).willReturn(jwt);

		OAuth2AuthorizedClientRefreshedEvent authorizedClientRefreshedEvent = new OAuth2AuthorizedClientRefreshedEvent(
				this.accessTokenResponse, this.authorizedClient);
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
			.isThrownBy(() -> this.eventListener.onApplicationEvent(authorizedClientRefreshedEvent))
			.withMessageContaining("Invalid authenticated at time")
			.extracting(OAuth2AuthenticationException::getError)
			.extracting(OAuth2Error::getErrorCode)
			.isEqualTo(INVALID_ID_TOKEN_ERROR);
		verify(this.securityContextHolderStrategy).getContext();
		verify(this.jwtDecoder).decode(this.jwt.getTokenValue());
		verifyNoMoreInteractions(this.securityContextHolderStrategy, this.jwtDecoder);
		verifyNoInteractions(this.userService, this.applicationEventPublisher);
	}

	@Test
	public void onApplicationEventWhenIdTokenAuthenticatedAtMatchesThenOidcUserRefreshedEventPublished() {
		Instant authTime = this.authentication.getPrincipal().getAttribute(IdTokenClaimNames.AUTH_TIME);
		Jwt jwt = createJwt().claim(IdTokenClaimNames.AUTH_TIME, authTime).build();
		SecurityContextImpl securityContext = new SecurityContextImpl(this.authentication);
		given(this.securityContextHolderStrategy.getContext()).willReturn(securityContext);
		given(this.jwtDecoder.decode(anyString())).willReturn(jwt);
		given(this.userService.loadUser(any(OidcUserRequest.class))).willReturn(this.oidcUser);

		OAuth2AuthorizedClientRefreshedEvent authorizedClientRefreshedEvent = new OAuth2AuthorizedClientRefreshedEvent(
				this.accessTokenResponse, this.authorizedClient);
		this.eventListener.onApplicationEvent(authorizedClientRefreshedEvent);

		verify(this.applicationEventPublisher).publishEvent(any(OidcUserRefreshedEvent.class));
		verifyNoMoreInteractions(this.applicationEventPublisher);
	}

	@Test
	public void onApplicationEventWhenIdTokenNonceDoesNotMatchThenThrowsOAuth2AuthenticationException() {
		Jwt jwt = createJwt().claim(IdTokenClaimNames.NONCE, "invalid").build();
		SecurityContextImpl securityContext = new SecurityContextImpl(this.authentication);
		given(this.securityContextHolderStrategy.getContext()).willReturn(securityContext);
		given(this.jwtDecoder.decode(anyString())).willReturn(jwt);

		OAuth2AuthorizedClientRefreshedEvent authorizedClientRefreshedEvent = new OAuth2AuthorizedClientRefreshedEvent(
				this.accessTokenResponse, this.authorizedClient);
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
			.isThrownBy(() -> this.eventListener.onApplicationEvent(authorizedClientRefreshedEvent))
			.withMessageContaining("Invalid nonce")
			.extracting(OAuth2AuthenticationException::getError)
			.extracting(OAuth2Error::getErrorCode)
			.isEqualTo(INVALID_NONCE_ERROR);
		verify(this.securityContextHolderStrategy).getContext();
		verify(this.jwtDecoder).decode(this.jwt.getTokenValue());
		verifyNoMoreInteractions(this.securityContextHolderStrategy, this.jwtDecoder);
		verifyNoInteractions(this.userService, this.applicationEventPublisher);
	}

	@Test
	public void onApplicationEventWhenIdTokenNonceMatchesThenOidcUserRefreshedEventPublished() {
		Jwt jwt = createJwt().claim(IdTokenClaimNames.NONCE, this.oidcUser.getNonce()).build();
		SecurityContextImpl securityContext = new SecurityContextImpl(this.authentication);
		given(this.securityContextHolderStrategy.getContext()).willReturn(securityContext);
		given(this.jwtDecoder.decode(anyString())).willReturn(jwt);
		given(this.userService.loadUser(any(OidcUserRequest.class))).willReturn(this.oidcUser);

		OAuth2AuthorizedClientRefreshedEvent authorizedClientRefreshedEvent = new OAuth2AuthorizedClientRefreshedEvent(
				this.accessTokenResponse, this.authorizedClient);
		this.eventListener.onApplicationEvent(authorizedClientRefreshedEvent);

		verify(this.applicationEventPublisher).publishEvent(any(OidcUserRefreshedEvent.class));
		verifyNoMoreInteractions(this.applicationEventPublisher);
	}

	@Test
	public void onApplicationEventWhenInvalidIdTokenThenThrowsOAuth2AuthenticationException() {
		SecurityContextImpl securityContext = new SecurityContextImpl(this.authentication);
		given(this.securityContextHolderStrategy.getContext()).willReturn(securityContext);
		given(this.jwtDecoder.decode(anyString())).willThrow(new JwtException("Invalid token"));

		OAuth2AuthorizedClientRefreshedEvent authorizedClientRefreshedEvent = new OAuth2AuthorizedClientRefreshedEvent(
				this.accessTokenResponse, this.authorizedClient);
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
			.isThrownBy(() -> this.eventListener.onApplicationEvent(authorizedClientRefreshedEvent))
			.extracting(OAuth2AuthenticationException::getError)
			.extracting(OAuth2Error::getErrorCode)
			.isEqualTo(INVALID_ID_TOKEN_ERROR);
		verify(this.securityContextHolderStrategy).getContext();
		verify(this.jwtDecoder).decode(this.jwt.getTokenValue());
		verifyNoMoreInteractions(this.securityContextHolderStrategy, this.jwtDecoder);
		verifyNoInteractions(this.userService, this.applicationEventPublisher);
	}

	@Test
	public void onApplicationEventWhenCustomAuthoritiesMapperSetThenUsed() {
		SecurityContextImpl securityContext = new SecurityContextImpl(this.authentication);
		given(this.securityContextHolderStrategy.getContext()).willReturn(securityContext);
		given(this.jwtDecoder.decode(anyString())).willReturn(this.jwt);
		given(this.userService.loadUser(any(OidcUserRequest.class))).willReturn(this.oidcUser);

		GrantedAuthoritiesMapper grantedAuthoritiesMapper = mock(GrantedAuthoritiesMapper.class);
		this.eventListener.setAuthoritiesMapper(grantedAuthoritiesMapper);

		OAuth2AuthorizedClientRefreshedEvent authorizedClientRefreshedEvent = new OAuth2AuthorizedClientRefreshedEvent(
				this.accessTokenResponse, this.authorizedClient);
		this.eventListener.onApplicationEvent(authorizedClientRefreshedEvent);

		verify(grantedAuthoritiesMapper).mapAuthorities(this.oidcUser.getAuthorities());
		verifyNoMoreInteractions(grantedAuthoritiesMapper);
	}

	private static OAuth2AuthorizedClient createAuthorizedClient(ClientRegistration clientRegistration) {
		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plus(30, ChronoUnit.SECONDS);
		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, ACCESS_TOKEN_VALUE,
				issuedAt, expiresAt, clientRegistration.getScopes());

		return new OAuth2AuthorizedClient(clientRegistration, SUBJECT, accessToken);
	}

	private static OAuth2AccessTokenResponse createAccessTokenResponse(String... scope) {
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

	private static Jwt.Builder createJwt() {
		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plus(1, ChronoUnit.MINUTES);
		return TestJwts.jwt()
			.issuer("https://surf.school")
			.subject(SUBJECT)
			.tokenValue(ID_TOKEN_VALUE)
			.issuedAt(issuedAt)
			.expiresAt(expiresAt)
			.audience(List.of("audience1", "audience2"));
	}

	private static OidcUser createOidcUser() {
		Instant issuedAt = Instant.now().minus(30, ChronoUnit.SECONDS);
		Instant expiresAt = issuedAt.plus(5, ChronoUnit.MINUTES);
		Map<String, Object> claims = new HashMap<>();
		claims.put(IdTokenClaimNames.ISS, "https://surf.school");
		claims.put(IdTokenClaimNames.SUB, SUBJECT);
		claims.put(IdTokenClaimNames.IAT, issuedAt);
		claims.put(IdTokenClaimNames.EXP, expiresAt);
		claims.put(IdTokenClaimNames.AUD, List.of("audience1", "audience2"));
		claims.put(IdTokenClaimNames.AUTH_TIME, issuedAt);
		claims.put(IdTokenClaimNames.NONCE, "nonce");
		OidcIdToken idToken = new OidcIdToken(ID_TOKEN_VALUE, issuedAt, expiresAt, claims);

		return new DefaultOidcUser(AuthorityUtils.createAuthorityList("OIDC_USER"), idToken);
	}

	private static OAuth2AuthenticationToken createAuthenticationToken(ClientRegistration clientRegistration,
			OidcUser oidcUser) {
		return new OAuth2AuthenticationToken(oidcUser, oidcUser.getAuthorities(),
				clientRegistration.getRegistrationId());
	}

	private static final class CustomOAuth2AuthenticationToken extends OAuth2AuthenticationToken {

		CustomOAuth2AuthenticationToken(OAuth2User principal, Collection<? extends GrantedAuthority> authorities,
				String authorizedClientRegistrationId) {
			super(principal, authorities, authorizedClientRegistrationId);
		}

	}

}
