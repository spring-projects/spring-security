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

package org.springframework.security.oauth2.server.authorization;

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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link OAuth2ClientRegistration}.
 *
 * @author Joe Grandja
 */
public class OAuth2ClientRegistrationTests {

	@Test
	public void buildWhenAllClaimsProvidedThenCreated() throws Exception {
		// @formatter:off
		Instant clientIdIssuedAt = Instant.now();
		Instant clientSecretExpiresAt = clientIdIssuedAt.plus(30, ChronoUnit.DAYS);
		OAuth2ClientRegistration clientRegistration = OAuth2ClientRegistration.builder()
				.clientId("client-id")
				.clientIdIssuedAt(clientIdIssuedAt)
				.clientSecret("client-secret")
				.clientSecretExpiresAt(clientSecretExpiresAt)
				.clientName("client-name")
				.redirectUri("https://client.example.com")
				.tokenEndpointAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue())
				.grantType(AuthorizationGrantType.AUTHORIZATION_CODE.getValue())
				.grantType(AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())
				.responseType(OAuth2AuthorizationResponseType.CODE.getValue())
				.scope("scope1")
				.scope("scope2")
				.jwkSetUrl("https://client.example.com/jwks")
				.claim("a-claim", "a-value")
				.build();
		// @formatter:on

		assertThat(clientRegistration.getClientId()).isEqualTo("client-id");
		assertThat(clientRegistration.getClientIdIssuedAt()).isEqualTo(clientIdIssuedAt);
		assertThat(clientRegistration.getClientSecret()).isEqualTo("client-secret");
		assertThat(clientRegistration.getClientSecretExpiresAt()).isEqualTo(clientSecretExpiresAt);
		assertThat(clientRegistration.getClientName()).isEqualTo("client-name");
		assertThat(clientRegistration.getRedirectUris()).containsOnly("https://client.example.com");
		assertThat(clientRegistration.getTokenEndpointAuthenticationMethod())
			.isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue());
		assertThat(clientRegistration.getGrantTypes()).containsExactlyInAnyOrder("authorization_code",
				"client_credentials");
		assertThat(clientRegistration.getResponseTypes()).containsOnly("code");
		assertThat(clientRegistration.getScopes()).containsExactlyInAnyOrder("scope1", "scope2");
		assertThat(clientRegistration.getJwkSetUrl()).isEqualTo(new URL("https://client.example.com/jwks"));
		assertThat(clientRegistration.getClaimAsString("a-claim")).isEqualTo("a-value");
	}

	@Test
	public void withClaimsWhenClaimsProvidedThenCreated() throws Exception {
		Instant clientIdIssuedAt = Instant.now();
		Instant clientSecretExpiresAt = clientIdIssuedAt.plus(30, ChronoUnit.DAYS);
		HashMap<String, Object> claims = new HashMap<>();
		claims.put(OAuth2ClientMetadataClaimNames.CLIENT_ID, "client-id");
		claims.put(OAuth2ClientMetadataClaimNames.CLIENT_ID_ISSUED_AT, clientIdIssuedAt);
		claims.put(OAuth2ClientMetadataClaimNames.CLIENT_SECRET, "client-secret");
		claims.put(OAuth2ClientMetadataClaimNames.CLIENT_SECRET_EXPIRES_AT, clientSecretExpiresAt);
		claims.put(OAuth2ClientMetadataClaimNames.CLIENT_NAME, "client-name");
		claims.put(OAuth2ClientMetadataClaimNames.REDIRECT_URIS,
				Collections.singletonList("https://client.example.com"));
		claims.put(OAuth2ClientMetadataClaimNames.TOKEN_ENDPOINT_AUTH_METHOD,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue());
		claims.put(OAuth2ClientMetadataClaimNames.GRANT_TYPES,
				Arrays.asList(AuthorizationGrantType.AUTHORIZATION_CODE.getValue(),
						AuthorizationGrantType.CLIENT_CREDENTIALS.getValue()));
		claims.put(OAuth2ClientMetadataClaimNames.RESPONSE_TYPES, Collections.singletonList("code"));
		claims.put(OAuth2ClientMetadataClaimNames.SCOPE, Arrays.asList("scope1", "scope2"));
		claims.put(OAuth2ClientMetadataClaimNames.JWKS_URI, "https://client.example.com/jwks");
		claims.put("a-claim", "a-value");

		OAuth2ClientRegistration clientRegistration = OAuth2ClientRegistration.withClaims(claims).build();

		assertThat(clientRegistration.getClientId()).isEqualTo("client-id");
		assertThat(clientRegistration.getClientIdIssuedAt()).isEqualTo(clientIdIssuedAt);
		assertThat(clientRegistration.getClientSecret()).isEqualTo("client-secret");
		assertThat(clientRegistration.getClientSecretExpiresAt()).isEqualTo(clientSecretExpiresAt);
		assertThat(clientRegistration.getClientName()).isEqualTo("client-name");
		assertThat(clientRegistration.getRedirectUris()).containsOnly("https://client.example.com");
		assertThat(clientRegistration.getTokenEndpointAuthenticationMethod())
			.isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue());
		assertThat(clientRegistration.getGrantTypes()).containsExactlyInAnyOrder("authorization_code",
				"client_credentials");
		assertThat(clientRegistration.getResponseTypes()).containsOnly("code");
		assertThat(clientRegistration.getScopes()).containsExactlyInAnyOrder("scope1", "scope2");
		assertThat(clientRegistration.getJwkSetUrl()).isEqualTo(new URL("https://client.example.com/jwks"));
		assertThat(clientRegistration.getClaimAsString("a-claim")).isEqualTo("a-value");
	}

	@Test
	public void withClaimsWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> OAuth2ClientRegistration.withClaims(null))
			.withMessage("claims cannot be empty");
	}

	@Test
	public void withClaimsWhenEmptyThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> OAuth2ClientRegistration.withClaims(Collections.emptyMap()))
			.withMessage("claims cannot be empty");
	}

	@Test
	public void buildWhenMissingClientIdThenThrowIllegalArgumentException() {
		OAuth2ClientRegistration.Builder builder = OAuth2ClientRegistration.builder().clientIdIssuedAt(Instant.now());

		assertThatIllegalArgumentException().isThrownBy(builder::build).withMessage("client_id cannot be null");
	}

	@Test
	public void buildWhenClientSecretAndMissingClientIdThenThrowIllegalArgumentException() {
		OAuth2ClientRegistration.Builder builder = OAuth2ClientRegistration.builder().clientSecret("client-secret");

		assertThatIllegalArgumentException().isThrownBy(builder::build).withMessage("client_id cannot be null");
	}

	@Test
	public void buildWhenClientIdIssuedAtNotInstantThenThrowIllegalArgumentException() {
		// @formatter:off
		OAuth2ClientRegistration.Builder builder = OAuth2ClientRegistration.builder()
				.clientId("client-id")
				.claim(OAuth2ClientMetadataClaimNames.CLIENT_ID_ISSUED_AT, "clientIdIssuedAt");
		// @formatter:on

		assertThatIllegalArgumentException().isThrownBy(builder::build)
			.withMessageStartingWith("client_id_issued_at must be of type Instant");
	}

	@Test
	public void buildWhenMissingClientSecretThenThrowIllegalArgumentException() {
		// @formatter:off
		OAuth2ClientRegistration.Builder builder = OAuth2ClientRegistration.builder()
				.clientId("client-id")
				.clientIdIssuedAt(Instant.now())
				.clientSecretExpiresAt(Instant.now().plus(30, ChronoUnit.DAYS));
		// @formatter:on

		assertThatIllegalArgumentException().isThrownBy(builder::build).withMessage("client_secret cannot be null");
	}

	@Test
	public void buildWhenClientSecretExpiresAtNotInstantThenThrowIllegalArgumentException() {
		// @formatter:off
		OAuth2ClientRegistration.Builder builder = OAuth2ClientRegistration.builder()
				.clientId("client-id")
				.clientIdIssuedAt(Instant.now())
				.clientSecret("client-secret")
				.claim(OAuth2ClientMetadataClaimNames.CLIENT_SECRET_EXPIRES_AT, "clientSecretExpiresAt");
		// @formatter:on

		assertThatIllegalArgumentException().isThrownBy(builder::build)
			.withMessageStartingWith("client_secret_expires_at must be of type Instant");
	}

	@Test
	public void buildWhenRedirectUrisNotListThenThrowIllegalArgumentException() {
		OAuth2ClientRegistration.Builder builder = OAuth2ClientRegistration.builder()
			.claim(OAuth2ClientMetadataClaimNames.REDIRECT_URIS, "redirectUris");

		assertThatIllegalArgumentException().isThrownBy(builder::build)
			.withMessageStartingWith("redirect_uris must be of type List");
	}

	@Test
	public void buildWhenRedirectUrisEmptyListThenThrowIllegalArgumentException() {
		OAuth2ClientRegistration.Builder builder = OAuth2ClientRegistration.builder()
			.claim(OAuth2ClientMetadataClaimNames.REDIRECT_URIS, Collections.emptyList());

		assertThatIllegalArgumentException().isThrownBy(builder::build).withMessage("redirect_uris cannot be empty");
	}

	@Test
	public void buildWhenRedirectUrisAddingOrRemovingThenCorrectValues() {
		// @formatter:off
		OAuth2ClientRegistration clientRegistration = OAuth2ClientRegistration.builder()
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
	public void buildWhenGrantTypesNotListThenThrowIllegalArgumentException() {
		OAuth2ClientRegistration.Builder builder = OAuth2ClientRegistration.builder()
			.claim(OAuth2ClientMetadataClaimNames.GRANT_TYPES, "grantTypes");

		assertThatIllegalArgumentException().isThrownBy(builder::build)
			.withMessageStartingWith("grant_types must be of type List");
	}

	@Test
	public void buildWhenGrantTypesEmptyListThenThrowIllegalArgumentException() {
		OAuth2ClientRegistration.Builder builder = OAuth2ClientRegistration.builder()
			.claim(OAuth2ClientMetadataClaimNames.GRANT_TYPES, Collections.emptyList());

		assertThatIllegalArgumentException().isThrownBy(builder::build).withMessage("grant_types cannot be empty");
	}

	@Test
	public void buildWhenGrantTypesAddingOrRemovingThenCorrectValues() {
		// @formatter:off
		OAuth2ClientRegistration clientRegistration = OAuth2ClientRegistration.builder()
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
		OAuth2ClientRegistration.Builder builder = OAuth2ClientRegistration.builder()
			.claim(OAuth2ClientMetadataClaimNames.RESPONSE_TYPES, "responseTypes");

		assertThatIllegalArgumentException().isThrownBy(builder::build)
			.withMessageStartingWith("response_types must be of type List");
	}

	@Test
	public void buildWhenResponseTypesEmptyListThenThrowIllegalArgumentException() {
		OAuth2ClientRegistration.Builder builder = OAuth2ClientRegistration.builder()
			.claim(OAuth2ClientMetadataClaimNames.RESPONSE_TYPES, Collections.emptyList());

		assertThatIllegalArgumentException().isThrownBy(builder::build).withMessage("response_types cannot be empty");
	}

	@Test
	public void buildWhenResponseTypesAddingOrRemovingThenCorrectValues() {
		// @formatter:off
		OAuth2ClientRegistration clientRegistration = OAuth2ClientRegistration.builder()
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
		OAuth2ClientRegistration.Builder builder = OAuth2ClientRegistration.builder()
			.claim(OAuth2ClientMetadataClaimNames.SCOPE, "scopes");

		assertThatIllegalArgumentException().isThrownBy(builder::build)
			.withMessageStartingWith("scope must be of type List");
	}

	@Test
	public void buildWhenScopesEmptyListThenThrowIllegalArgumentException() {
		OAuth2ClientRegistration.Builder builder = OAuth2ClientRegistration.builder()
			.claim(OAuth2ClientMetadataClaimNames.SCOPE, Collections.emptyList());

		assertThatIllegalArgumentException().isThrownBy(builder::build).withMessage("scope cannot be empty");
	}

	@Test
	public void buildWhenScopesAddingOrRemovingThenCorrectValues() {
		// @formatter:off
		OAuth2ClientRegistration clientRegistration = OAuth2ClientRegistration.builder()
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
		OAuth2ClientRegistration.Builder builder = OAuth2ClientRegistration.builder()
			.claim(OAuth2ClientMetadataClaimNames.JWKS_URI, "not an url");

		assertThatIllegalArgumentException().isThrownBy(builder::build).withMessage("jwksUri must be a valid URL");
	}

	@Test
	public void claimWhenNameNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> OAuth2ClientRegistration.builder().claim(null, "claim-value"))
			.withMessage("name cannot be empty");
	}

	@Test
	public void claimWhenValueNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> OAuth2ClientRegistration.builder().claim("claim-name", null))
			.withMessage("value cannot be null");
	}

	@Test
	public void claimsWhenRemovingClaimThenNotPresent() {
		// @formatter:off
		OAuth2ClientRegistration clientRegistration = OAuth2ClientRegistration.builder()
				.redirectUri("https://client.example.com")
				.claim("claim-name", "claim-value")
				.claims((claims) -> claims.remove("claim-name"))
				.build();
		// @formatter:on

		assertThat(clientRegistration.hasClaim("claim-name")).isFalse();
	}

	@Test
	public void claimsWhenAddingClaimThenPresent() {
		// @formatter:off
		OAuth2ClientRegistration clientRegistration = OAuth2ClientRegistration.builder()
				.claim("claim-name", "claim-value")
				.build();
		// @formatter:on

		assertThat(clientRegistration.hasClaim("claim-name")).isTrue();
	}

}
