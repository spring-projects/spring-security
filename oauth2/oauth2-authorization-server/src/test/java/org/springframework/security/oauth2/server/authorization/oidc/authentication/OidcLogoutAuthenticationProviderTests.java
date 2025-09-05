/*
 * Copyright 2020-2024 the original author or authors.
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
package org.springframework.security.oauth2.server.authorization.oidc.authentication;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.function.Consumer;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.TestOAuth2Authorizations;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.context.TestAuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link OidcLogoutAuthenticationProvider}.
 *
 * @author Joe Grandja
 */
public class OidcLogoutAuthenticationProviderTests {

	private static final OAuth2TokenType ID_TOKEN_TOKEN_TYPE = new OAuth2TokenType(OidcParameterNames.ID_TOKEN);

	private RegisteredClientRepository registeredClientRepository;

	private OAuth2AuthorizationService authorizationService;

	private SessionRegistry sessionRegistry;

	private AuthorizationServerSettings authorizationServerSettings;

	private OidcLogoutAuthenticationProvider authenticationProvider;

	@BeforeEach
	public void setUp() {
		this.registeredClientRepository = mock(RegisteredClientRepository.class);
		this.authorizationService = mock(OAuth2AuthorizationService.class);
		this.sessionRegistry = mock(SessionRegistry.class);
		this.authorizationServerSettings = AuthorizationServerSettings.builder().issuer("https://provider.com").build();
		TestAuthorizationServerContext authorizationServerContext = new TestAuthorizationServerContext(
				this.authorizationServerSettings, null);
		AuthorizationServerContextHolder.setContext(authorizationServerContext);
		this.authenticationProvider = new OidcLogoutAuthenticationProvider(this.registeredClientRepository,
				this.authorizationService, this.sessionRegistry);
	}

	@AfterEach
	public void cleanup() {
		AuthorizationServerContextHolder.resetContext();
	}

	@Test
	public void constructorWhenRegisteredClientRepositoryNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(
					() -> new OidcLogoutAuthenticationProvider(null, this.authorizationService, this.sessionRegistry))
			.withMessage("registeredClientRepository cannot be null");
	}

	@Test
	public void constructorWhenAuthorizationServiceNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(
				() -> new OidcLogoutAuthenticationProvider(this.registeredClientRepository, null, this.sessionRegistry))
			.withMessage("authorizationService cannot be null");
	}

	@Test
	public void constructorWhenSessionRegistryNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> new OidcLogoutAuthenticationProvider(this.registeredClientRepository,
					this.authorizationService, null))
			.withMessage("sessionRegistry cannot be null");
	}

	@Test
	public void supportsWhenTypeOidcLogoutAuthenticationTokenThenReturnTrue() {
		assertThat(this.authenticationProvider.supports(OidcLogoutAuthenticationToken.class)).isTrue();
	}

	@Test
	public void authenticateWhenIdTokenNotFoundThenThrowOAuth2AuthenticationException() {
		TestingAuthenticationToken principal = new TestingAuthenticationToken("principal", "credentials");

		OidcLogoutAuthenticationToken authentication = new OidcLogoutAuthenticationToken("id-token", principal,
				"session-1", null, null, null);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
			.satisfies((error) -> {
				assertThat(error.getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_TOKEN);
				assertThat(error.getDescription()).contains("id_token_hint");
			});

		verify(this.authorizationService).findByToken(eq(authentication.getIdTokenHint()), eq(ID_TOKEN_TOKEN_TYPE));
	}

	@Test
	public void authenticateWhenIdTokenInvalidatedThenThrowOAuth2AuthenticationException() {
		TestingAuthenticationToken principal = new TestingAuthenticationToken("principal", "credentials");
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OidcIdToken idToken = OidcIdToken.withTokenValue("id-token")
			.issuer("https://provider.com")
			.subject(principal.getName())
			.issuedAt(Instant.now().minusSeconds(60).truncatedTo(ChronoUnit.MILLIS))
			.expiresAt(Instant.now().plusSeconds(60).truncatedTo(ChronoUnit.MILLIS))
			.build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient)
			.principalName(principal.getName())
			.token(idToken, (metadata) -> {
				metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, idToken.getClaims());
				metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, true);
			})
			.build();
		given(this.authorizationService.findByToken(eq(idToken.getTokenValue()), eq(ID_TOKEN_TOKEN_TYPE)))
			.willReturn(authorization);

		OidcLogoutAuthenticationToken authentication = new OidcLogoutAuthenticationToken(idToken.getTokenValue(),
				principal, "session-1", null, null, null);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
			.satisfies((error) -> {
				assertThat(error.getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_TOKEN);
				assertThat(error.getDescription()).contains("id_token_hint");
			});

		verify(this.authorizationService).findByToken(eq(authentication.getIdTokenHint()), eq(ID_TOKEN_TOKEN_TYPE));
	}

	@Test
	public void authenticateWhenMissingAudienceThenThrowOAuth2AuthenticationException() {
		TestingAuthenticationToken principal = new TestingAuthenticationToken("principal", "credentials");
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OidcIdToken idToken = OidcIdToken.withTokenValue("id-token")
			.issuer("https://provider.com")
			.subject(principal.getName())
			.issuedAt(Instant.now().minusSeconds(60).truncatedTo(ChronoUnit.MILLIS))
			.expiresAt(Instant.now().plusSeconds(60).truncatedTo(ChronoUnit.MILLIS))
			.build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient)
			.principalName(principal.getName())
			.token(idToken,
					(metadata) -> metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, idToken.getClaims()))
			.build();
		given(this.authorizationService.findByToken(eq(idToken.getTokenValue()), eq(ID_TOKEN_TOKEN_TYPE)))
			.willReturn(authorization);
		given(this.registeredClientRepository.findById(eq(authorization.getRegisteredClientId())))
			.willReturn(registeredClient);

		OidcLogoutAuthenticationToken authentication = new OidcLogoutAuthenticationToken(idToken.getTokenValue(),
				principal, "session-1", null, null, null);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
			.satisfies((error) -> {
				assertThat(error.getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_TOKEN);
				assertThat(error.getDescription()).contains(IdTokenClaimNames.AUD);
			});
		verify(this.authorizationService).findByToken(eq(authentication.getIdTokenHint()), eq(ID_TOKEN_TOKEN_TYPE));
		verify(this.registeredClientRepository).findById(eq(authorization.getRegisteredClientId()));
	}

	@Test
	public void authenticateWhenInvalidAudienceThenThrowOAuth2AuthenticationException() {
		TestingAuthenticationToken principal = new TestingAuthenticationToken("principal", "credentials");
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OidcIdToken idToken = OidcIdToken.withTokenValue("id-token")
			.issuer("https://provider.com")
			.subject(principal.getName())
			.audience(Collections.singleton(registeredClient.getClientId() + "-invalid"))
			.issuedAt(Instant.now().minusSeconds(60).truncatedTo(ChronoUnit.MILLIS))
			.expiresAt(Instant.now().plusSeconds(60).truncatedTo(ChronoUnit.MILLIS))
			.build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient)
			.principalName(principal.getName())
			.token(idToken,
					(metadata) -> metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, idToken.getClaims()))
			.build();
		given(this.authorizationService.findByToken(eq(idToken.getTokenValue()), eq(ID_TOKEN_TOKEN_TYPE)))
			.willReturn(authorization);
		given(this.registeredClientRepository.findById(eq(authorization.getRegisteredClientId())))
			.willReturn(registeredClient);

		OidcLogoutAuthenticationToken authentication = new OidcLogoutAuthenticationToken(idToken.getTokenValue(),
				principal, "session-1", null, null, null);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
			.satisfies((error) -> {
				assertThat(error.getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_TOKEN);
				assertThat(error.getDescription()).contains(IdTokenClaimNames.AUD);
			});
		verify(this.authorizationService).findByToken(eq(authentication.getIdTokenHint()), eq(ID_TOKEN_TOKEN_TYPE));
		verify(this.registeredClientRepository).findById(eq(authorization.getRegisteredClientId()));
	}

	@Test
	public void authenticateWhenInvalidClientIdThenThrowOAuth2AuthenticationException() {
		TestingAuthenticationToken principal = new TestingAuthenticationToken("principal", "credentials");
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OidcIdToken idToken = OidcIdToken.withTokenValue("id-token")
			.issuer("https://provider.com")
			.subject(principal.getName())
			.audience(Collections.singleton(registeredClient.getClientId()))
			.issuedAt(Instant.now().minusSeconds(60).truncatedTo(ChronoUnit.MILLIS))
			.expiresAt(Instant.now().plusSeconds(60).truncatedTo(ChronoUnit.MILLIS))
			.build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient)
			.principalName(principal.getName())
			.token(idToken,
					(metadata) -> metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, idToken.getClaims()))
			.build();
		given(this.authorizationService.findByToken(eq(idToken.getTokenValue()), eq(ID_TOKEN_TOKEN_TYPE)))
			.willReturn(authorization);
		given(this.registeredClientRepository.findById(eq(authorization.getRegisteredClientId())))
			.willReturn(registeredClient);

		OidcLogoutAuthenticationToken authentication = new OidcLogoutAuthenticationToken(idToken.getTokenValue(),
				principal, "session-1", registeredClient.getClientId() + "-invalid", null, null);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
			.satisfies((error) -> {
				assertThat(error.getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST);
				assertThat(error.getDescription()).contains(OAuth2ParameterNames.CLIENT_ID);
			});
		verify(this.authorizationService).findByToken(eq(authentication.getIdTokenHint()), eq(ID_TOKEN_TOKEN_TYPE));
		verify(this.registeredClientRepository).findById(eq(authorization.getRegisteredClientId()));
	}

	@Test
	public void authenticateWhenInvalidPostLogoutRedirectUriThenThrowOAuth2AuthenticationException() {
		TestingAuthenticationToken principal = new TestingAuthenticationToken("principal", "credentials");
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OidcIdToken idToken = OidcIdToken.withTokenValue("id-token")
			.issuer("https://provider.com")
			.subject(principal.getName())
			.audience(Collections.singleton(registeredClient.getClientId()))
			.issuedAt(Instant.now().minusSeconds(60).truncatedTo(ChronoUnit.MILLIS))
			.expiresAt(Instant.now().plusSeconds(60).truncatedTo(ChronoUnit.MILLIS))
			.build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient)
			.principalName(principal.getName())
			.token(idToken,
					(metadata) -> metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, idToken.getClaims()))
			.build();
		given(this.authorizationService.findByToken(eq(idToken.getTokenValue()), eq(ID_TOKEN_TOKEN_TYPE)))
			.willReturn(authorization);
		given(this.registeredClientRepository.findById(eq(authorization.getRegisteredClientId())))
			.willReturn(registeredClient);

		OidcLogoutAuthenticationToken authentication = new OidcLogoutAuthenticationToken(idToken.getTokenValue(),
				principal, "session-1", registeredClient.getClientId(), "https://example.com/callback-1-invalid", null);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
			.satisfies((error) -> {
				assertThat(error.getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST);
				assertThat(error.getDescription()).contains("post_logout_redirect_uri");
			});
		verify(this.authorizationService).findByToken(eq(authentication.getIdTokenHint()), eq(ID_TOKEN_TOKEN_TYPE));
		verify(this.registeredClientRepository).findById(eq(authorization.getRegisteredClientId()));
	}

	@Test
	public void setAuthenticationValidatorWhenNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.authenticationProvider.setAuthenticationValidator(null))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("authenticationValidator cannot be null");
	}

	@Test
	public void authenticateWhenCustomAuthenticationValidatorThenUsed() throws NoSuchAlgorithmException {
		TestingAuthenticationToken principal = new TestingAuthenticationToken("principal", "credentials");
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		String sessionId = "session-1";
		OidcIdToken idToken = OidcIdToken.withTokenValue("id-token")
			.issuer("https://provider.com")
			.subject(principal.getName())
			.audience(Collections.singleton(registeredClient.getClientId()))
			.issuedAt(Instant.now().minusSeconds(60).truncatedTo(ChronoUnit.MILLIS))
			.expiresAt(Instant.now().plusSeconds(60).truncatedTo(ChronoUnit.MILLIS))
			.claim("sid", createHash(sessionId))
			.build();

		@SuppressWarnings("unchecked")
		Consumer<OidcLogoutAuthenticationContext> authenticationValidator = mock(Consumer.class);
		this.authenticationProvider.setAuthenticationValidator(authenticationValidator);

		authenticateValidIdToken(principal, registeredClient, sessionId, idToken);
		verify(authenticationValidator).accept(any(OidcLogoutAuthenticationContext.class));
	}

	@Test
	public void authenticateWhenMissingSubThenThrowOAuth2AuthenticationException() {
		TestingAuthenticationToken principal = new TestingAuthenticationToken("principal", "credentials");
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OidcIdToken idToken = OidcIdToken.withTokenValue("id-token")
			.issuer("https://provider.com")
			.audience(Collections.singleton(registeredClient.getClientId()))
			.issuedAt(Instant.now().minusSeconds(60).truncatedTo(ChronoUnit.MILLIS))
			.expiresAt(Instant.now().plusSeconds(60).truncatedTo(ChronoUnit.MILLIS))
			.build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient)
			.principalName(principal.getName())
			.token(idToken,
					(metadata) -> metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, idToken.getClaims()))
			.build();
		given(this.authorizationService.findByToken(eq(idToken.getTokenValue()), eq(ID_TOKEN_TOKEN_TYPE)))
			.willReturn(authorization);
		given(this.registeredClientRepository.findById(eq(authorization.getRegisteredClientId())))
			.willReturn(registeredClient);

		principal.setAuthenticated(true);

		OidcLogoutAuthenticationToken authentication = new OidcLogoutAuthenticationToken(idToken.getTokenValue(),
				principal, "session-1", null, null, null);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
			.satisfies((error) -> {
				assertThat(error.getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_TOKEN);
				assertThat(error.getDescription()).contains("sub");
			});
		verify(this.authorizationService).findByToken(eq(authentication.getIdTokenHint()), eq(ID_TOKEN_TOKEN_TYPE));
		verify(this.registeredClientRepository).findById(eq(authorization.getRegisteredClientId()));
	}

	// gh-1235
	@Test
	public void authenticateWhenInvalidPrincipalThenThrowOAuth2AuthenticationException() {
		TestingAuthenticationToken principal = new TestingAuthenticationToken("principal", "credentials");
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OidcIdToken idToken = OidcIdToken.withTokenValue("id-token")
			.issuer("https://provider.com")
			.subject(principal.getName())
			.audience(Collections.singleton(registeredClient.getClientId()))
			.issuedAt(Instant.now().minusSeconds(60).truncatedTo(ChronoUnit.MILLIS))
			.expiresAt(Instant.now().plusSeconds(60).truncatedTo(ChronoUnit.MILLIS))
			.build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient)
			.principalName(principal.getName())
			.token(idToken,
					(metadata) -> metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, idToken.getClaims()))
			.build();
		given(this.authorizationService.findByToken(eq(idToken.getTokenValue()), eq(ID_TOKEN_TOKEN_TYPE)))
			.willReturn(authorization);
		given(this.registeredClientRepository.findById(eq(authorization.getRegisteredClientId())))
			.willReturn(registeredClient);

		principal.setAuthenticated(true);

		TestingAuthenticationToken otherPrincipal = new TestingAuthenticationToken("other-principal", "credentials");
		otherPrincipal.setAuthenticated(true);

		OidcLogoutAuthenticationToken authentication = new OidcLogoutAuthenticationToken(idToken.getTokenValue(),
				otherPrincipal, "session-1", null, null, null);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
			.satisfies((error) -> {
				assertThat(error.getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_TOKEN);
				assertThat(error.getDescription()).contains("sub");
			});
		verify(this.authorizationService).findByToken(eq(authentication.getIdTokenHint()), eq(ID_TOKEN_TOKEN_TYPE));
		verify(this.registeredClientRepository).findById(eq(authorization.getRegisteredClientId()));
	}

	@Test
	public void authenticateWhenMissingSidThenThrowOAuth2AuthenticationException() {
		TestingAuthenticationToken principal = new TestingAuthenticationToken("principal", "credentials");
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OidcIdToken idToken = OidcIdToken.withTokenValue("id-token")
			.issuer("https://provider.com")
			.subject(principal.getName())
			.audience(Collections.singleton(registeredClient.getClientId()))
			.issuedAt(Instant.now().minusSeconds(60).truncatedTo(ChronoUnit.MILLIS))
			.expiresAt(Instant.now().plusSeconds(60).truncatedTo(ChronoUnit.MILLIS))
			.build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient)
			.principalName(principal.getName())
			.token(idToken,
					(metadata) -> metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, idToken.getClaims()))
			.build();
		given(this.authorizationService.findByToken(eq(idToken.getTokenValue()), eq(ID_TOKEN_TOKEN_TYPE)))
			.willReturn(authorization);
		given(this.registeredClientRepository.findById(eq(authorization.getRegisteredClientId())))
			.willReturn(registeredClient);

		String sessionId = "session-1";
		List<SessionInformation> sessions = Collections
			.singletonList(new SessionInformation(principal.getPrincipal(), sessionId, Date.from(Instant.now())));
		given(this.sessionRegistry.getAllSessions(eq(principal.getPrincipal()), eq(true))).willReturn(sessions);

		principal.setAuthenticated(true);

		OidcLogoutAuthenticationToken authentication = new OidcLogoutAuthenticationToken(idToken.getTokenValue(),
				principal, sessionId, null, null, null);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
			.satisfies((error) -> {
				assertThat(error.getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_TOKEN);
				assertThat(error.getDescription()).contains("sid");
			});
		verify(this.authorizationService).findByToken(eq(authentication.getIdTokenHint()), eq(ID_TOKEN_TOKEN_TYPE));
		verify(this.registeredClientRepository).findById(eq(authorization.getRegisteredClientId()));
	}

	@Test
	public void authenticateWhenInvalidSidThenThrowOAuth2AuthenticationException() {
		TestingAuthenticationToken principal = new TestingAuthenticationToken("principal", "credentials");
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OidcIdToken idToken = OidcIdToken.withTokenValue("id-token")
			.issuer("https://provider.com")
			.subject(principal.getName())
			.audience(Collections.singleton(registeredClient.getClientId()))
			.issuedAt(Instant.now().minusSeconds(60).truncatedTo(ChronoUnit.MILLIS))
			.expiresAt(Instant.now().plusSeconds(60).truncatedTo(ChronoUnit.MILLIS))
			.claim("sid", "other-session")
			.build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient)
			.principalName(principal.getName())
			.token(idToken,
					(metadata) -> metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, idToken.getClaims()))
			.build();
		given(this.authorizationService.findByToken(eq(idToken.getTokenValue()), eq(ID_TOKEN_TOKEN_TYPE)))
			.willReturn(authorization);
		given(this.registeredClientRepository.findById(eq(authorization.getRegisteredClientId())))
			.willReturn(registeredClient);

		String sessionId = "session-1";
		List<SessionInformation> sessions = Collections
			.singletonList(new SessionInformation(principal.getPrincipal(), sessionId, Date.from(Instant.now())));
		given(this.sessionRegistry.getAllSessions(eq(principal.getPrincipal()), eq(true))).willReturn(sessions);

		principal.setAuthenticated(true);

		OidcLogoutAuthenticationToken authentication = new OidcLogoutAuthenticationToken(idToken.getTokenValue(),
				principal, sessionId, null, null, null);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
			.satisfies((error) -> {
				assertThat(error.getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_TOKEN);
				assertThat(error.getDescription()).contains("sid");
			});
		verify(this.authorizationService).findByToken(eq(authentication.getIdTokenHint()), eq(ID_TOKEN_TOKEN_TYPE));
		verify(this.registeredClientRepository).findById(eq(authorization.getRegisteredClientId()));
	}

	@Test
	public void authenticateWhenValidIdTokenThenAuthenticated() throws Exception {
		TestingAuthenticationToken principal = new TestingAuthenticationToken("principal", "credentials");
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		String sessionId = "session-1";
		OidcIdToken idToken = OidcIdToken.withTokenValue("id-token")
			.issuer("https://provider.com")
			.subject(principal.getName())
			.audience(Collections.singleton(registeredClient.getClientId()))
			.issuedAt(Instant.now().minusSeconds(60).truncatedTo(ChronoUnit.MILLIS))
			.expiresAt(Instant.now().plusSeconds(60).truncatedTo(ChronoUnit.MILLIS))
			.claim("sid", createHash(sessionId))
			.build();
		authenticateValidIdToken(principal, registeredClient, sessionId, idToken);
	}

	// gh-1440
	@Test
	public void authenticateWhenValidExpiredIdTokenThenAuthenticated() throws Exception {
		TestingAuthenticationToken principal = new TestingAuthenticationToken("principal", "credentials");
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		String sessionId = "session-1";
		OidcIdToken idToken = OidcIdToken.withTokenValue("id-token")
			.issuer("https://provider.com")
			.subject(principal.getName())
			.audience(Collections.singleton(registeredClient.getClientId()))
			.issuedAt(Instant.now().minusSeconds(60).truncatedTo(ChronoUnit.MILLIS))
			.expiresAt(Instant.now().minusSeconds(30).truncatedTo(ChronoUnit.MILLIS)) // Expired
			.claim("sid", createHash(sessionId))
			.build();
		authenticateValidIdToken(principal, registeredClient, sessionId, idToken);
	}

	private void authenticateValidIdToken(Authentication principal, RegisteredClient registeredClient, String sessionId,
			OidcIdToken idToken) {
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient)
			.principalName(principal.getName())
			.token(idToken,
					(metadata) -> metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, idToken.getClaims()))
			.build();
		given(this.authorizationService.findByToken(eq(idToken.getTokenValue()), eq(ID_TOKEN_TOKEN_TYPE)))
			.willReturn(authorization);
		given(this.registeredClientRepository.findById(eq(authorization.getRegisteredClientId())))
			.willReturn(registeredClient);

		SessionInformation sessionInformation = new SessionInformation(principal.getPrincipal(), sessionId,
				Date.from(Instant.now()));
		List<SessionInformation> sessions = Collections.singletonList(sessionInformation);
		given(this.sessionRegistry.getAllSessions(eq(principal.getPrincipal()), eq(true))).willReturn(sessions);

		principal.setAuthenticated(true);
		String postLogoutRedirectUri = registeredClient.getPostLogoutRedirectUris().toArray(new String[0])[0];
		String state = "state";

		OidcLogoutAuthenticationToken authentication = new OidcLogoutAuthenticationToken(idToken.getTokenValue(),
				principal, sessionId, registeredClient.getClientId(), postLogoutRedirectUri, state);

		OidcLogoutAuthenticationToken authenticationResult = (OidcLogoutAuthenticationToken) this.authenticationProvider
			.authenticate(authentication);

		verify(this.authorizationService).findByToken(eq(authentication.getIdTokenHint()), eq(ID_TOKEN_TOKEN_TYPE));
		verify(this.registeredClientRepository).findById(eq(authorization.getRegisteredClientId()));

		assertThat(authenticationResult.getPrincipal()).isEqualTo(principal);
		assertThat(authenticationResult.getCredentials().toString()).isEmpty();
		assertThat(authenticationResult.getIdToken()).isEqualTo(idToken);
		assertThat(authenticationResult.getSessionId()).isEqualTo(sessionInformation.getSessionId());
		assertThat(authenticationResult.getClientId()).isEqualTo(registeredClient.getClientId());
		assertThat(authenticationResult.getPostLogoutRedirectUri()).isEqualTo(postLogoutRedirectUri);
		assertThat(authenticationResult.getState()).isEqualTo(state);
		assertThat(authenticationResult.isAuthenticated()).isTrue();
	}

	private static String createHash(String value) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		byte[] digest = md.digest(value.getBytes(StandardCharsets.US_ASCII));
		return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
	}

}
