/*
 * Copyright 2020-2023 the original author or authors.
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
package org.springframework.security.oauth2.server.authorization.oidc;

import java.net.URL;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;

import org.junit.jupiter.api.Test;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link OidcClientRegistration}.
 *
 * @author Ovidiu Popa
 * @author Joe Grandja
 */
public class OidcClientRegistrationTests {

	// @formatter:off
	private final OidcClientRegistration.Builder minimalBuilder =
			OidcClientRegistration.builder()
					.redirectUri("https://client.example.com");
	// @formatter:on

	@Test
	public void buildWhenAllClaimsProvidedThenCreated() throws Exception {
		// @formatter:off
		Instant clientIdIssuedAt = Instant.now();
		Instant clientSecretExpiresAt = clientIdIssuedAt.plus(30, ChronoUnit.DAYS);
		OidcClientRegistration clientRegistration = OidcClientRegistration.builder()
				.clientId("client-id")
				.clientIdIssuedAt(clientIdIssuedAt)
				.clientSecret("client-secret")
				.clientSecretExpiresAt(clientSecretExpiresAt)
				.clientName("client-name")
				.redirectUri("https://client.example.com")
				.postLogoutRedirectUri("https://client.example.com/oidc-post-logout")
				.tokenEndpointAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_JWT.getValue())
				.tokenEndpointAuthenticationSigningAlgorithm(MacAlgorithm.HS256.getName())
				.grantType(AuthorizationGrantType.AUTHORIZATION_CODE.getValue())
				.grantType(AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())
				.responseType(OAuth2AuthorizationResponseType.CODE.getValue())
				.scope("scope1")
				.scope("scope2")
				.jwkSetUrl("https://client.example.com/jwks")
				.idTokenSignedResponseAlgorithm(SignatureAlgorithm.RS256.getName())
				.registrationAccessToken("registration-access-token")
				.registrationClientUrl("https://auth-server.com/connect/register?client_id=1")
				.claim("a-claim", "a-value")
				.build();
		// @formatter:on

		assertThat(clientRegistration.getClientId()).isEqualTo("client-id");
		assertThat(clientRegistration.getClientIdIssuedAt()).isEqualTo(clientIdIssuedAt);
		assertThat(clientRegistration.getClientSecret()).isEqualTo("client-secret");
		assertThat(clientRegistration.getClientSecretExpiresAt()).isEqualTo(clientSecretExpiresAt);
		assertThat(clientRegistration.getClientName()).isEqualTo("client-name");
		assertThat(clientRegistration.getRedirectUris()).containsOnly("https://client.example.com");
		assertThat(clientRegistration.getPostLogoutRedirectUris())
			.containsOnly("https://client.example.com/oidc-post-logout");
		assertThat(clientRegistration.getTokenEndpointAuthenticationMethod())
			.isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_JWT.getValue());
		assertThat(clientRegistration.getTokenEndpointAuthenticationSigningAlgorithm())
			.isEqualTo(MacAlgorithm.HS256.getName());
		assertThat(clientRegistration.getGrantTypes()).containsExactlyInAnyOrder("authorization_code",
				"client_credentials");
		assertThat(clientRegistration.getResponseTypes()).containsOnly("code");
		assertThat(clientRegistration.getScopes()).containsExactlyInAnyOrder("scope1", "scope2");
		assertThat(clientRegistration.getJwkSetUrl()).isEqualTo(new URL("https://client.example.com/jwks"));
		assertThat(clientRegistration.getIdTokenSignedResponseAlgorithm()).isEqualTo("RS256");
		assertThat(clientRegistration.getRegistrationAccessToken()).isEqualTo("registration-access-token");
		assertThat(clientRegistration.getRegistrationClientUrl().toString())
			.isEqualTo("https://auth-server.com/connect/register?client_id=1");
		assertThat(clientRegistration.getClaimAsString("a-claim")).isEqualTo("a-value");
	}

	@Test
	public void buildWhenOnlyRequiredClaimsProvidedThenCreated() {
		OidcClientRegistration clientRegistration = this.minimalBuilder.build();
		assertThat(clientRegistration.getRedirectUris()).containsOnly("https://client.example.com");
	}

	@Test
	public void withClaimsWhenClaimsProvidedThenCreated() throws Exception {
		Instant clientIdIssuedAt = Instant.now();
		Instant clientSecretExpiresAt = clientIdIssuedAt.plus(30, ChronoUnit.DAYS);
		HashMap<String, Object> claims = new HashMap<>();
		claims.put(OidcClientMetadataClaimNames.CLIENT_ID, "client-id");
		claims.put(OidcClientMetadataClaimNames.CLIENT_ID_ISSUED_AT, clientIdIssuedAt);
		claims.put(OidcClientMetadataClaimNames.CLIENT_SECRET, "client-secret");
		claims.put(OidcClientMetadataClaimNames.CLIENT_SECRET_EXPIRES_AT, clientSecretExpiresAt);
		claims.put(OidcClientMetadataClaimNames.CLIENT_NAME, "client-name");
		claims.put(OidcClientMetadataClaimNames.REDIRECT_URIS, Collections.singletonList("https://client.example.com"));
		claims.put(OidcClientMetadataClaimNames.POST_LOGOUT_REDIRECT_URIS,
				Collections.singletonList("https://client.example.com/oidc-post-logout"));
		claims.put(OidcClientMetadataClaimNames.TOKEN_ENDPOINT_AUTH_METHOD,
				ClientAuthenticationMethod.CLIENT_SECRET_JWT.getValue());
		claims.put(OidcClientMetadataClaimNames.TOKEN_ENDPOINT_AUTH_SIGNING_ALG, MacAlgorithm.HS256.getName());
		claims.put(OidcClientMetadataClaimNames.GRANT_TYPES,
				Arrays.asList(AuthorizationGrantType.AUTHORIZATION_CODE.getValue(),
						AuthorizationGrantType.CLIENT_CREDENTIALS.getValue()));
		claims.put(OidcClientMetadataClaimNames.RESPONSE_TYPES, Collections.singletonList("code"));
		claims.put(OidcClientMetadataClaimNames.SCOPE, Arrays.asList("scope1", "scope2"));
		claims.put(OidcClientMetadataClaimNames.JWKS_URI, "https://client.example.com/jwks");
		claims.put(OidcClientMetadataClaimNames.ID_TOKEN_SIGNED_RESPONSE_ALG, SignatureAlgorithm.RS256.getName());
		claims.put(OidcClientMetadataClaimNames.REGISTRATION_ACCESS_TOKEN, "registration-access-token");
		claims.put(OidcClientMetadataClaimNames.REGISTRATION_CLIENT_URI,
				"https://auth-server.com/connect/register?client_id=1");
		claims.put("a-claim", "a-value");

		OidcClientRegistration clientRegistration = OidcClientRegistration.withClaims(claims).build();

		assertThat(clientRegistration.getClientId()).isEqualTo("client-id");
		assertThat(clientRegistration.getClientIdIssuedAt()).isEqualTo(clientIdIssuedAt);
		assertThat(clientRegistration.getClientSecret()).isEqualTo("client-secret");
		assertThat(clientRegistration.getClientSecretExpiresAt()).isEqualTo(clientSecretExpiresAt);
		assertThat(clientRegistration.getClientName()).isEqualTo("client-name");
		assertThat(clientRegistration.getRedirectUris()).containsOnly("https://client.example.com");
		assertThat(clientRegistration.getPostLogoutRedirectUris())
			.containsOnly("https://client.example.com/oidc-post-logout");
		assertThat(clientRegistration.getTokenEndpointAuthenticationMethod())
			.isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_JWT.getValue());
		assertThat(clientRegistration.getTokenEndpointAuthenticationSigningAlgorithm())
			.isEqualTo(MacAlgorithm.HS256.getName());
		assertThat(clientRegistration.getGrantTypes()).containsExactlyInAnyOrder("authorization_code",
				"client_credentials");
		assertThat(clientRegistration.getResponseTypes()).containsOnly("code");
		assertThat(clientRegistration.getScopes()).containsExactlyInAnyOrder("scope1", "scope2");
		assertThat(clientRegistration.getJwkSetUrl()).isEqualTo(new URL("https://client.example.com/jwks"));
		assertThat(clientRegistration.getIdTokenSignedResponseAlgorithm()).isEqualTo("RS256");
		assertThat(clientRegistration.getRegistrationAccessToken()).isEqualTo("registration-access-token");
		assertThat(clientRegistration.getRegistrationClientUrl().toString())
			.isEqualTo("https://auth-server.com/connect/register?client_id=1");
		assertThat(clientRegistration.getClaimAsString("a-claim")).isEqualTo("a-value");
	}

	@Test
	public void withClaimsWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> OidcClientRegistration.withClaims(null))
			.withMessage("claims cannot be empty");
	}

	@Test
	public void withClaimsWhenEmptyThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> OidcClientRegistration.withClaims(Collections.emptyMap()))
			.withMessage("claims cannot be empty");
	}

	@Test
	public void buildWhenMissingClientIdThenThrowIllegalArgumentException() {
		OidcClientRegistration.Builder builder = this.minimalBuilder.clientIdIssuedAt(Instant.now());

		assertThatIllegalArgumentException().isThrownBy(builder::build).withMessage("client_id cannot be null");
	}

	@Test
	public void buildWhenClientSecretAndMissingClientIdThenThrowIllegalArgumentException() {
		OidcClientRegistration.Builder builder = this.minimalBuilder.clientSecret("client-secret");

		assertThatIllegalArgumentException().isThrownBy(builder::build).withMessage("client_id cannot be null");
	}

	@Test
	public void buildWhenClientIdIssuedAtNotInstantThenThrowIllegalArgumentException() {
		// @formatter:off
		OidcClientRegistration.Builder builder = this.minimalBuilder
				.clientId("client-id")
				.claim(OidcClientMetadataClaimNames.CLIENT_ID_ISSUED_AT, "clientIdIssuedAt");
		// @formatter:on

		assertThatIllegalArgumentException().isThrownBy(builder::build)
			.withMessageStartingWith("client_id_issued_at must be of type Instant");
	}

	@Test
	public void buildWhenMissingClientSecretThenThrowIllegalArgumentException() {
		// @formatter:off
		OidcClientRegistration.Builder builder = this.minimalBuilder
				.clientId("client-id")
				.clientIdIssuedAt(Instant.now())
				.clientSecretExpiresAt(Instant.now().plus(30, ChronoUnit.DAYS));
		// @formatter:on

		assertThatIllegalArgumentException().isThrownBy(builder::build).withMessage("client_secret cannot be null");
	}

	@Test
	public void buildWhenClientSecretExpiresAtNotInstantThenThrowIllegalArgumentException() {
		// @formatter:off
		OidcClientRegistration.Builder builder = this.minimalBuilder
				.clientId("client-id")
				.clientIdIssuedAt(Instant.now())
				.clientSecret("client-secret")
				.claim(OidcClientMetadataClaimNames.CLIENT_SECRET_EXPIRES_AT, "clientSecretExpiresAt");
		// @formatter:on

		assertThatIllegalArgumentException().isThrownBy(builder::build)
			.withMessageStartingWith("client_secret_expires_at must be of type Instant");
	}

	@Test
	public void buildWhenMissingRedirectUrisThenThrowIllegalArgumentException() {
		OidcClientRegistration.Builder builder = OidcClientRegistration.builder().clientName("client-name");

		assertThatIllegalArgumentException().isThrownBy(builder::build).withMessage("redirect_uris cannot be null");
	}

	@Test
	public void buildWhenRedirectUrisNotListThenThrowIllegalArgumentException() {
		OidcClientRegistration.Builder builder = OidcClientRegistration.builder()
			.claim(OidcClientMetadataClaimNames.REDIRECT_URIS, "redirectUris");

		assertThatIllegalArgumentException().isThrownBy(builder::build)
			.withMessageStartingWith("redirect_uris must be of type List");
	}

	@Test
	public void buildWhenRedirectUrisEmptyListThenThrowIllegalArgumentException() {
		OidcClientRegistration.Builder builder = OidcClientRegistration.builder()
			.claim(OidcClientMetadataClaimNames.REDIRECT_URIS, Collections.emptyList());

		assertThatIllegalArgumentException().isThrownBy(builder::build).withMessage("redirect_uris cannot be empty");
	}

	@Test
	public void buildWhenRedirectUrisAddingOrRemovingThenCorrectValues() {
		// @formatter:off
		OidcClientRegistration clientRegistration = this.minimalBuilder
				.redirectUri("https://client1.example.com")
				.redirectUris((redirectUris) -> {
					redirectUris.clear();
					redirectUris.add("https://client2.example.com");
				})
				.build();
		// @formatter:on

		assertThat(clientRegistration.getRedirectUris()).containsExactly("https://client2.example.com");
	}

	@Test
	public void buildWhenPostLogoutRedirectUrisNotListThenThrowIllegalArgumentException() {
		OidcClientRegistration.Builder builder = this.minimalBuilder
			.claim(OidcClientMetadataClaimNames.POST_LOGOUT_REDIRECT_URIS, "postLogoutRedirectUris");

		assertThatIllegalArgumentException().isThrownBy(builder::build)
			.withMessageStartingWith("post_logout_redirect_uris must be of type List");
	}

	@Test
	public void buildWhenPostLogoutRedirectUrisEmptyListThenThrowIllegalArgumentException() {
		OidcClientRegistration.Builder builder = this.minimalBuilder
			.claim(OidcClientMetadataClaimNames.POST_LOGOUT_REDIRECT_URIS, Collections.emptyList());

		assertThatIllegalArgumentException().isThrownBy(builder::build)
			.withMessage("post_logout_redirect_uris cannot be empty");
	}

	@Test
	public void buildWhenPostLogoutRedirectUrisAddingOrRemovingThenCorrectValues() {
		// @formatter:off
		OidcClientRegistration clientRegistration = this.minimalBuilder
				.postLogoutRedirectUri("https://client1.example.com/oidc-post-logout")
				.postLogoutRedirectUris((postLogoutRedirectUris) -> {
					postLogoutRedirectUris.clear();
					postLogoutRedirectUris.add("https://client2.example.com/oidc-post-logout");
				})
				.build();
		// @formatter:on

		assertThat(clientRegistration.getPostLogoutRedirectUris())
			.containsExactly("https://client2.example.com/oidc-post-logout");
	}

	@Test
	public void buildWhenGrantTypesNotListThenThrowIllegalArgumentException() {
		OidcClientRegistration.Builder builder = this.minimalBuilder.claim(OidcClientMetadataClaimNames.GRANT_TYPES,
				"grantTypes");

		assertThatIllegalArgumentException().isThrownBy(builder::build)
			.withMessageStartingWith("grant_types must be of type List");
	}

	@Test
	public void buildWhenGrantTypesEmptyListThenThrowIllegalArgumentException() {
		OidcClientRegistration.Builder builder = this.minimalBuilder.claim(OidcClientMetadataClaimNames.GRANT_TYPES,
				Collections.emptyList());

		assertThatIllegalArgumentException().isThrownBy(builder::build).withMessage("grant_types cannot be empty");
	}

	@Test
	public void buildWhenGrantTypesAddingOrRemovingThenCorrectValues() {
		// @formatter:off
		OidcClientRegistration clientRegistration = this.minimalBuilder
				.grantType("authorization_code")
				.grantTypes((grantTypes) -> {
					grantTypes.clear();
					grantTypes.add("client_credentials");
				})
				.build();
		// @formatter:on

		assertThat(clientRegistration.getGrantTypes()).containsExactly("client_credentials");
	}

	@Test
	public void buildWhenResponseTypesNotListThenThrowIllegalArgumentException() {
		OidcClientRegistration.Builder builder = this.minimalBuilder.claim(OidcClientMetadataClaimNames.RESPONSE_TYPES,
				"responseTypes");

		assertThatIllegalArgumentException().isThrownBy(builder::build)
			.withMessageStartingWith("response_types must be of type List");
	}

	@Test
	public void buildWhenResponseTypesEmptyListThenThrowIllegalArgumentException() {
		OidcClientRegistration.Builder builder = this.minimalBuilder.claim(OidcClientMetadataClaimNames.RESPONSE_TYPES,
				Collections.emptyList());

		assertThatIllegalArgumentException().isThrownBy(builder::build).withMessage("response_types cannot be empty");
	}

	@Test
	public void buildWhenResponseTypesAddingOrRemovingThenCorrectValues() {
		// @formatter:off
		OidcClientRegistration clientRegistration = this.minimalBuilder
				.responseType("token")
				.responseTypes((responseTypes) -> {
					responseTypes.clear();
					responseTypes.add("code");
				})
				.build();
		// @formatter:on

		assertThat(clientRegistration.getResponseTypes()).containsExactly("code");
	}

	@Test
	public void buildWhenScopesNotListThenThrowIllegalArgumentException() {
		OidcClientRegistration.Builder builder = this.minimalBuilder.claim(OidcClientMetadataClaimNames.SCOPE,
				"scopes");

		assertThatIllegalArgumentException().isThrownBy(builder::build)
			.withMessageStartingWith("scope must be of type List");
	}

	@Test
	public void buildWhenScopesEmptyListThenThrowIllegalArgumentException() {
		OidcClientRegistration.Builder builder = this.minimalBuilder.claim(OidcClientMetadataClaimNames.SCOPE,
				Collections.emptyList());

		assertThatIllegalArgumentException().isThrownBy(builder::build).withMessage("scope cannot be empty");
	}

	@Test
	public void buildWhenScopesAddingOrRemovingThenCorrectValues() {
		// @formatter:off
		OidcClientRegistration clientRegistration = this.minimalBuilder
				.scope("should-be-removed")
				.scopes((scopes) -> {
					scopes.clear();
					scopes.add("scope1");
				})
				.build();
		// @formatter:on

		assertThat(clientRegistration.getScopes()).containsExactly("scope1");
	}

	@Test
	public void buildWhenJwksUriNotUrlThenThrowIllegalArgumentException() {
		OidcClientRegistration.Builder builder = this.minimalBuilder.claim(OidcClientMetadataClaimNames.JWKS_URI,
				"not an url");

		assertThatIllegalArgumentException().isThrownBy(builder::build).withMessage("jwksUri must be a valid URL");
	}

	@Test
	public void claimWhenNameNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> OidcClientRegistration.builder().claim(null, "claim-value"))
			.withMessage("name cannot be empty");
	}

	@Test
	public void claimWhenValueNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> OidcClientRegistration.builder().claim("claim-name", null))
			.withMessage("value cannot be null");
	}

	@Test
	public void claimsWhenRemovingClaimThenNotPresent() {
		// @formatter:off
		OidcClientRegistration clientRegistration = this.minimalBuilder
				.claim("claim-name", "claim-value")
				.claims((claims) -> claims.remove("claim-name"))
				.build();
		// @formatter:on

		assertThat(clientRegistration.hasClaim("claim-name")).isFalse();
	}

	@Test
	public void claimsWhenAddingClaimThenPresent() {
		// @formatter:off
		OidcClientRegistration clientRegistration = this.minimalBuilder
				.claim("claim-name", "claim-value")
				.build();
		// @formatter:on

		assertThat(clientRegistration.hasClaim("claim-name")).isTrue();
	}

}
