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
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;

import org.junit.jupiter.api.Test;

import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithms;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationServerMetadata.Builder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link OAuth2AuthorizationServerMetadata}.
 *
 * @author Daniel Garnier-Moiroux
 */
public class OAuth2AuthorizationServerMetadataTests {

	// @formatter:off
	private final Builder minimalBuilder =
			OAuth2AuthorizationServerMetadata.builder()
					.issuer("https://example.com")
					.authorizationEndpoint("https://example.com/oauth2/authorize")
					.tokenEndpoint("https://example.com/oauth2/token")
					.responseType("code");
	// @formatter:on

	@Test
	public void buildWhenAllClaimsProvidedThenCreated() {
		OAuth2AuthorizationServerMetadata authorizationServerMetadata = OAuth2AuthorizationServerMetadata.builder()
			.issuer("https://example.com")
			.authorizationEndpoint("https://example.com/oauth2/authorize")
			.pushedAuthorizationRequestEndpoint("https://example.com/oauth2/par")
			.tokenEndpoint("https://example.com/oauth2/token")
			.tokenEndpointAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue())
			.jwkSetUrl("https://example.com/oauth2/jwks")
			.scope("openid")
			.responseType("code")
			.grantType("authorization_code")
			.grantType("client_credentials")
			.tokenRevocationEndpoint("https://example.com/oauth2/revoke")
			.tokenRevocationEndpointAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue())
			.tokenIntrospectionEndpoint("https://example.com/oauth2/introspect")
			.tokenIntrospectionEndpointAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue())
			.codeChallengeMethod("S256")
			.tlsClientCertificateBoundAccessTokens(true)
			.dPoPSigningAlgorithm(JwsAlgorithms.RS256)
			.dPoPSigningAlgorithm(JwsAlgorithms.ES256)
			.claim("a-claim", "a-value")
			.build();

		assertThat(authorizationServerMetadata.getIssuer()).isEqualTo(url("https://example.com"));
		assertThat(authorizationServerMetadata.getAuthorizationEndpoint())
			.isEqualTo(url("https://example.com/oauth2/authorize"));
		assertThat(authorizationServerMetadata.getPushedAuthorizationRequestEndpoint())
			.isEqualTo(url("https://example.com/oauth2/par"));
		assertThat(authorizationServerMetadata.getTokenEndpoint()).isEqualTo(url("https://example.com/oauth2/token"));
		assertThat(authorizationServerMetadata.getTokenEndpointAuthenticationMethods())
			.containsExactly(ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue());
		assertThat(authorizationServerMetadata.getJwkSetUrl()).isEqualTo(url("https://example.com/oauth2/jwks"));
		assertThat(authorizationServerMetadata.getScopes()).containsExactly("openid");
		assertThat(authorizationServerMetadata.getResponseTypes()).containsExactly("code");
		assertThat(authorizationServerMetadata.getGrantTypes()).containsExactlyInAnyOrder("authorization_code",
				"client_credentials");
		assertThat(authorizationServerMetadata.getTokenRevocationEndpoint())
			.isEqualTo(url("https://example.com/oauth2/revoke"));
		assertThat(authorizationServerMetadata.getTokenRevocationEndpointAuthenticationMethods())
			.containsExactly(ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue());
		assertThat(authorizationServerMetadata.getTokenIntrospectionEndpoint())
			.isEqualTo(url("https://example.com/oauth2/introspect"));
		assertThat(authorizationServerMetadata.getTokenIntrospectionEndpointAuthenticationMethods())
			.containsExactly(ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue());
		assertThat(authorizationServerMetadata.getCodeChallengeMethods()).containsExactly("S256");
		assertThat(authorizationServerMetadata.isTlsClientCertificateBoundAccessTokens()).isTrue();
		assertThat(authorizationServerMetadata.getDPoPSigningAlgorithms()).containsExactly(JwsAlgorithms.RS256,
				JwsAlgorithms.ES256);
		assertThat(authorizationServerMetadata.getClaimAsString("a-claim")).isEqualTo("a-value");
	}

	@Test
	public void buildWhenOnlyRequiredClaimsProvidedThenCreated() {
		OAuth2AuthorizationServerMetadata authorizationServerMetadata = OAuth2AuthorizationServerMetadata.builder()
			.issuer("https://example.com")
			.authorizationEndpoint("https://example.com/oauth2/authorize")
			.tokenEndpoint("https://example.com/oauth2/token")
			.responseType("code")
			.build();

		assertThat(authorizationServerMetadata.getIssuer()).isEqualTo(url("https://example.com"));
		assertThat(authorizationServerMetadata.getAuthorizationEndpoint())
			.isEqualTo(url("https://example.com/oauth2/authorize"));
		assertThat(authorizationServerMetadata.getPushedAuthorizationRequestEndpoint()).isNull();
		assertThat(authorizationServerMetadata.getTokenEndpoint()).isEqualTo(url("https://example.com/oauth2/token"));
		assertThat(authorizationServerMetadata.getTokenEndpointAuthenticationMethods()).isNull();
		assertThat(authorizationServerMetadata.getJwkSetUrl()).isNull();
		assertThat(authorizationServerMetadata.getScopes()).isNull();
		assertThat(authorizationServerMetadata.getResponseTypes()).containsExactly("code");
		assertThat(authorizationServerMetadata.getGrantTypes()).isNull();
		assertThat(authorizationServerMetadata.getTokenRevocationEndpoint()).isNull();
		assertThat(authorizationServerMetadata.getTokenRevocationEndpointAuthenticationMethods()).isNull();
		assertThat(authorizationServerMetadata.getTokenIntrospectionEndpoint()).isNull();
		assertThat(authorizationServerMetadata.getTokenIntrospectionEndpointAuthenticationMethods()).isNull();
		assertThat(authorizationServerMetadata.getCodeChallengeMethods()).isNull();
		assertThat(authorizationServerMetadata.getDPoPSigningAlgorithms()).isNull();
	}

	@Test
	public void withClaimsWhenClaimsProvidedThenCreated() {
		HashMap<String, Object> claims = new HashMap<>();
		claims.put(OAuth2AuthorizationServerMetadataClaimNames.ISSUER, "https://example.com");
		claims.put(OAuth2AuthorizationServerMetadataClaimNames.AUTHORIZATION_ENDPOINT,
				"https://example.com/oauth2/authorize");
		claims.put(OAuth2AuthorizationServerMetadataClaimNames.PUSHED_AUTHORIZATION_REQUEST_ENDPOINT,
				"https://example.com/oauth2/par");
		claims.put(OAuth2AuthorizationServerMetadataClaimNames.TOKEN_ENDPOINT, "https://example.com/oauth2/token");
		claims.put(OAuth2AuthorizationServerMetadataClaimNames.JWKS_URI, "https://example.com/oauth2/jwks");
		claims.put(OAuth2AuthorizationServerMetadataClaimNames.SCOPES_SUPPORTED, Collections.singletonList("openid"));
		claims.put(OAuth2AuthorizationServerMetadataClaimNames.RESPONSE_TYPES_SUPPORTED,
				Collections.singletonList("code"));
		claims.put(OAuth2AuthorizationServerMetadataClaimNames.REVOCATION_ENDPOINT,
				"https://example.com/oauth2/revoke");
		claims.put(OAuth2AuthorizationServerMetadataClaimNames.INTROSPECTION_ENDPOINT,
				"https://example.com/oauth2/introspect");
		claims.put("some-claim", "some-value");

		OAuth2AuthorizationServerMetadata authorizationServerMetadata = OAuth2AuthorizationServerMetadata
			.withClaims(claims)
			.build();

		assertThat(authorizationServerMetadata.getIssuer()).isEqualTo(url("https://example.com"));
		assertThat(authorizationServerMetadata.getAuthorizationEndpoint())
			.isEqualTo(url("https://example.com/oauth2/authorize"));
		assertThat(authorizationServerMetadata.getPushedAuthorizationRequestEndpoint())
			.isEqualTo(url("https://example.com/oauth2/par"));
		assertThat(authorizationServerMetadata.getTokenEndpoint()).isEqualTo(url("https://example.com/oauth2/token"));
		assertThat(authorizationServerMetadata.getTokenEndpointAuthenticationMethods()).isNull();
		assertThat(authorizationServerMetadata.getJwkSetUrl()).isEqualTo(url("https://example.com/oauth2/jwks"));
		assertThat(authorizationServerMetadata.getScopes()).containsExactly("openid");
		assertThat(authorizationServerMetadata.getResponseTypes()).containsExactly("code");
		assertThat(authorizationServerMetadata.getGrantTypes()).isNull();
		assertThat(authorizationServerMetadata.getTokenRevocationEndpoint())
			.isEqualTo(url("https://example.com/oauth2/revoke"));
		assertThat(authorizationServerMetadata.getTokenRevocationEndpointAuthenticationMethods()).isNull();
		assertThat(authorizationServerMetadata.getTokenIntrospectionEndpoint())
			.isEqualTo(url("https://example.com/oauth2/introspect"));
		assertThat(authorizationServerMetadata.getTokenIntrospectionEndpointAuthenticationMethods()).isNull();
		assertThat(authorizationServerMetadata.getCodeChallengeMethods()).isNull();
		assertThat(authorizationServerMetadata.getDPoPSigningAlgorithms()).isNull();
		assertThat(authorizationServerMetadata.getClaimAsString("some-claim")).isEqualTo("some-value");
	}

	@Test
	public void withClaimsWhenClaimsWithUrlsProvidedThenCreated() {
		HashMap<String, Object> claims = new HashMap<>();
		claims.put(OAuth2AuthorizationServerMetadataClaimNames.ISSUER, url("https://example.com"));
		claims.put(OAuth2AuthorizationServerMetadataClaimNames.AUTHORIZATION_ENDPOINT,
				url("https://example.com/oauth2/authorize"));
		claims.put(OAuth2AuthorizationServerMetadataClaimNames.PUSHED_AUTHORIZATION_REQUEST_ENDPOINT,
				url("https://example.com/oauth2/par"));
		claims.put(OAuth2AuthorizationServerMetadataClaimNames.TOKEN_ENDPOINT, url("https://example.com/oauth2/token"));
		claims.put(OAuth2AuthorizationServerMetadataClaimNames.JWKS_URI, url("https://example.com/oauth2/jwks"));
		claims.put(OAuth2AuthorizationServerMetadataClaimNames.RESPONSE_TYPES_SUPPORTED,
				Collections.singletonList("code"));
		claims.put(OAuth2AuthorizationServerMetadataClaimNames.REVOCATION_ENDPOINT,
				url("https://example.com/oauth2/revoke"));
		claims.put(OAuth2AuthorizationServerMetadataClaimNames.INTROSPECTION_ENDPOINT,
				url("https://example.com/oauth2/introspect"));
		claims.put("some-claim", "some-value");

		OAuth2AuthorizationServerMetadata authorizationServerMetadata = OAuth2AuthorizationServerMetadata
			.withClaims(claims)
			.build();

		assertThat(authorizationServerMetadata.getIssuer()).isEqualTo(url("https://example.com"));
		assertThat(authorizationServerMetadata.getAuthorizationEndpoint())
			.isEqualTo(url("https://example.com/oauth2/authorize"));
		assertThat(authorizationServerMetadata.getPushedAuthorizationRequestEndpoint())
			.isEqualTo(url("https://example.com/oauth2/par"));
		assertThat(authorizationServerMetadata.getTokenEndpoint()).isEqualTo(url("https://example.com/oauth2/token"));
		assertThat(authorizationServerMetadata.getTokenEndpointAuthenticationMethods()).isNull();
		assertThat(authorizationServerMetadata.getJwkSetUrl()).isEqualTo(url("https://example.com/oauth2/jwks"));
		assertThat(authorizationServerMetadata.getScopes()).isNull();
		assertThat(authorizationServerMetadata.getResponseTypes()).containsExactly("code");
		assertThat(authorizationServerMetadata.getGrantTypes()).isNull();
		assertThat(authorizationServerMetadata.getTokenRevocationEndpoint())
			.isEqualTo(url("https://example.com/oauth2/revoke"));
		assertThat(authorizationServerMetadata.getTokenRevocationEndpointAuthenticationMethods()).isNull();
		assertThat(authorizationServerMetadata.getTokenIntrospectionEndpoint())
			.isEqualTo(url("https://example.com/oauth2/introspect"));
		assertThat(authorizationServerMetadata.getTokenIntrospectionEndpointAuthenticationMethods()).isNull();
		assertThat(authorizationServerMetadata.getCodeChallengeMethods()).isNull();
		assertThat(authorizationServerMetadata.getDPoPSigningAlgorithms()).isNull();
		assertThat(authorizationServerMetadata.getClaimAsString("some-claim")).isEqualTo("some-value");
	}

	@Test
	public void withClaimsWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> OAuth2AuthorizationServerMetadata.withClaims(null))
			.withMessage("claims cannot be empty");
	}

	@Test
	public void withClaimsWhenMissingRequiredClaimsThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> OAuth2AuthorizationServerMetadata.withClaims(Collections.emptyMap()))
			.withMessage("claims cannot be empty");
	}

	@Test
	public void buildWhenCalledTwiceThenGeneratesTwoConfigurations() {
		OAuth2AuthorizationServerMetadata first = this.minimalBuilder.grantType("client_credentials").build();

		OAuth2AuthorizationServerMetadata second = this.minimalBuilder.claims((claims) -> {
			List<String> newGrantTypes = new ArrayList<>();
			newGrantTypes.add("authorization_code");
			newGrantTypes.add("custom_grant");
			claims.put(OAuth2AuthorizationServerMetadataClaimNames.GRANT_TYPES_SUPPORTED, newGrantTypes);
		}).build();

		assertThat(first.getGrantTypes()).containsExactly("client_credentials");
		assertThat(second.getGrantTypes()).containsExactlyInAnyOrder("authorization_code", "custom_grant");
	}

	@Test
	public void buildWhenMissingIssuerThenThrowIllegalArgumentException() {
		Builder builder = this.minimalBuilder
			.claims((claims) -> claims.remove(OAuth2AuthorizationServerMetadataClaimNames.ISSUER));

		assertThatIllegalArgumentException().isThrownBy(builder::build).withMessage("issuer cannot be null");
	}

	@Test
	public void buildWhenIssuerNotUrlThenThrowIllegalArgumentException() {
		Builder builder = this.minimalBuilder
			.claims((claims) -> claims.put(OAuth2AuthorizationServerMetadataClaimNames.ISSUER, "not an url"));

		assertThatIllegalArgumentException().isThrownBy(builder::build).withMessage("issuer must be a valid URL");
	}

	@Test
	public void buildWhenMissingAuthorizationEndpointThenThrowIllegalArgumentException() {
		Builder builder = this.minimalBuilder
			.claims((claims) -> claims.remove(OAuth2AuthorizationServerMetadataClaimNames.AUTHORIZATION_ENDPOINT));

		assertThatIllegalArgumentException().isThrownBy(builder::build)
			.withMessage("authorizationEndpoint cannot be null");
	}

	@Test
	public void buildWhenAuthorizationEndpointNotUrlThenThrowIllegalArgumentException() {
		Builder builder = this.minimalBuilder.claims((claims) -> claims
			.put(OAuth2AuthorizationServerMetadataClaimNames.AUTHORIZATION_ENDPOINT, "not an url"));

		assertThatIllegalArgumentException().isThrownBy(builder::build)
			.withMessage("authorizationEndpoint must be a valid URL");
	}

	@Test
	public void buildWhenPushedAuthorizationRequestEndpointNotUrlThenThrowIllegalArgumentException() {
		Builder builder = this.minimalBuilder.claims((claims) -> claims
			.put(OAuth2AuthorizationServerMetadataClaimNames.PUSHED_AUTHORIZATION_REQUEST_ENDPOINT, "not an url"));

		assertThatIllegalArgumentException().isThrownBy(builder::build)
			.withMessage("pushedAuthorizationRequestEndpoint must be a valid URL");
	}

	@Test
	public void buildWhenMissingTokenEndpointThenThrowsIllegalArgumentException() {
		Builder builder = this.minimalBuilder
			.claims((claims) -> claims.remove(OAuth2AuthorizationServerMetadataClaimNames.TOKEN_ENDPOINT));

		assertThatIllegalArgumentException().isThrownBy(builder::build).withMessage("tokenEndpoint cannot be null");
	}

	@Test
	public void buildWhenTokenEndpointNotUrlThenThrowIllegalArgumentException() {
		Builder builder = this.minimalBuilder
			.claims((claims) -> claims.put(OAuth2AuthorizationServerMetadataClaimNames.TOKEN_ENDPOINT, "not an url"));

		assertThatIllegalArgumentException().isThrownBy(builder::build)
			.withMessage("tokenEndpoint must be a valid URL");
	}

	@Test
	public void buildWhenTokenEndpointAuthenticationMethodsNotListThenThrowIllegalArgumentException() {
		Builder builder = this.minimalBuilder.claims((claims) -> claims
			.put(OAuth2AuthorizationServerMetadataClaimNames.TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED, "not-a-list"));

		assertThatIllegalArgumentException().isThrownBy(builder::build)
			.withMessageStartingWith("tokenEndpointAuthenticationMethods must be of type List");
	}

	@Test
	public void buildWhenTokenEndpointAuthenticationMethodsEmptyListThenThrowIllegalArgumentException() {
		Builder builder = this.minimalBuilder.claims((claims) -> claims.put(
				OAuth2AuthorizationServerMetadataClaimNames.TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED,
				Collections.emptyList()));

		assertThatIllegalArgumentException().isThrownBy(builder::build)
			.withMessage("tokenEndpointAuthenticationMethods cannot be empty");
	}

	@Test
	public void buildWhenTokenEndpointAuthenticationMethodsAddingOrRemovingThenCorrectValues() {
		OAuth2AuthorizationServerMetadata authorizationServerMetadata = this.minimalBuilder
			.tokenEndpointAuthenticationMethod("should-be-removed")
			.tokenEndpointAuthenticationMethods((authMethods) -> {
				authMethods.clear();
				authMethods.add("some-authentication-method");
			})
			.build();

		assertThat(authorizationServerMetadata.getTokenEndpointAuthenticationMethods())
			.containsExactly("some-authentication-method");
	}

	@Test
	public void buildWhenJwksUriNotUrlThenThrowIllegalArgumentException() {
		Builder builder = this.minimalBuilder
			.claims((claims) -> claims.put(OAuth2AuthorizationServerMetadataClaimNames.JWKS_URI, "not an url"));

		assertThatIllegalArgumentException().isThrownBy(builder::build).withMessage("jwksUri must be a valid URL");
	}

	@Test
	public void buildWhenScopesNotListThenThrowIllegalArgumentException() {
		Builder builder = this.minimalBuilder
			.claims((claims) -> claims.put(OAuth2AuthorizationServerMetadataClaimNames.SCOPES_SUPPORTED, "not-a-list"));

		assertThatIllegalArgumentException().isThrownBy(builder::build)
			.withMessageStartingWith("scopes must be of type List");
	}

	@Test
	public void buildWhenScopesEmptyListThenThrowIllegalArgumentException() {
		Builder builder = this.minimalBuilder.claims((claims) -> claims
			.put(OAuth2AuthorizationServerMetadataClaimNames.SCOPES_SUPPORTED, Collections.emptyList()));

		assertThatIllegalArgumentException().isThrownBy(builder::build).withMessage("scopes cannot be empty");
	}

	@Test
	public void buildWhenScopesAddingOrRemovingThenCorrectValues() {
		OAuth2AuthorizationServerMetadata authorizationServerMetadata = this.minimalBuilder.scope("should-be-removed")
			.scopes((scopes) -> {
				scopes.clear();
				scopes.add("some-scope");
			})
			.build();

		assertThat(authorizationServerMetadata.getScopes()).containsExactly("some-scope");
	}

	@Test
	public void buildWhenMissingResponseTypesThenThrowIllegalArgumentException() {
		Builder builder = this.minimalBuilder
			.claims((claims) -> claims.remove(OAuth2AuthorizationServerMetadataClaimNames.RESPONSE_TYPES_SUPPORTED));

		assertThatIllegalArgumentException().isThrownBy(builder::build).withMessage("responseTypes cannot be null");
	}

	@Test
	public void buildWhenResponseTypesNotListThenThrowIllegalArgumentException() {
		Builder builder = this.minimalBuilder.claims((claims) -> claims
			.put(OAuth2AuthorizationServerMetadataClaimNames.RESPONSE_TYPES_SUPPORTED, "not-a-list"));

		assertThatIllegalArgumentException().isThrownBy(builder::build)
			.withMessageStartingWith("responseTypes must be of type List");
	}

	@Test
	public void buildWhenResponseTypesEmptyListThenThrowIllegalArgumentException() {
		Builder builder = this.minimalBuilder.claims((claims) -> claims
			.put(OAuth2AuthorizationServerMetadataClaimNames.RESPONSE_TYPES_SUPPORTED, Collections.emptyList()));

		assertThatIllegalArgumentException().isThrownBy(builder::build).withMessage("responseTypes cannot be empty");
	}

	@Test
	public void buildWhenResponseTypesAddingOrRemovingThenCorrectValues() {
		OAuth2AuthorizationServerMetadata authorizationServerMetadata = this.minimalBuilder
			.responseType("should-be-removed")
			.responseTypes((responseTypes) -> {
				responseTypes.clear();
				responseTypes.add("some-response-type");
			})
			.build();

		assertThat(authorizationServerMetadata.getResponseTypes()).containsExactly("some-response-type");
	}

	@Test
	public void buildWhenResponseTypesNotPresentAndAddingThenCorrectValues() {
		OAuth2AuthorizationServerMetadata authorizationServerMetadata = this.minimalBuilder
			.claims((claims) -> claims.remove(OAuth2AuthorizationServerMetadataClaimNames.RESPONSE_TYPES_SUPPORTED))
			.responseTypes((responseTypes) -> responseTypes.add("some-response-type"))
			.build();

		assertThat(authorizationServerMetadata.getResponseTypes()).containsExactly("some-response-type");
	}

	@Test
	public void buildWhenGrantTypesNotListThenThrowIllegalArgumentException() {
		Builder builder = this.minimalBuilder.claims((claims) -> claims
			.put(OAuth2AuthorizationServerMetadataClaimNames.GRANT_TYPES_SUPPORTED, "not-a-list"));

		assertThatIllegalArgumentException().isThrownBy(builder::build)
			.withMessageStartingWith("grantTypes must be of type List");
	}

	@Test
	public void buildWhenGrantTypesEmptyListThenThrowIllegalArgumentException() {
		Builder builder = this.minimalBuilder.claims((claims) -> claims
			.put(OAuth2AuthorizationServerMetadataClaimNames.GRANT_TYPES_SUPPORTED, Collections.emptyList()));

		assertThatIllegalArgumentException().isThrownBy(builder::build).withMessage("grantTypes cannot be empty");
	}

	@Test
	public void buildWhenGrantTypesAddingOrRemovingThenCorrectValues() {
		OAuth2AuthorizationServerMetadata authorizationServerMetadata = this.minimalBuilder
			.grantType("should-be-removed")
			.grantTypes((grantTypes) -> {
				grantTypes.clear();
				grantTypes.add("some-grant-type");
			})
			.build();

		assertThat(authorizationServerMetadata.getGrantTypes()).containsExactly("some-grant-type");
	}

	@Test
	public void buildWhenTokenRevocationEndpointNotUrlThenThrowIllegalArgumentException() {
		Builder builder = this.minimalBuilder.tokenRevocationEndpoint("not a valid URL");

		assertThatIllegalArgumentException().isThrownBy(builder::build)
			.withMessage("tokenRevocationEndpoint must be a valid URL");
	}

	@Test
	public void buildWhenTokenRevocationEndpointAuthenticationMethodsNotListThenThrowIllegalArgumentException() {
		Builder builder = this.minimalBuilder.claims((claims) -> claims
			.put(OAuth2AuthorizationServerMetadataClaimNames.REVOCATION_ENDPOINT_AUTH_METHODS_SUPPORTED, "not-a-list"));

		assertThatIllegalArgumentException().isThrownBy(builder::build)
			.withMessageStartingWith("tokenRevocationEndpointAuthenticationMethods must be of type List");
	}

	@Test
	public void buildWhenTokenRevocationEndpointAuthenticationMethodsEmptyListThenThrowIllegalArgumentException() {
		Builder builder = this.minimalBuilder.claims((claims) -> claims.put(
				OAuth2AuthorizationServerMetadataClaimNames.REVOCATION_ENDPOINT_AUTH_METHODS_SUPPORTED,
				Collections.emptyList()));

		assertThatIllegalArgumentException().isThrownBy(builder::build)
			.withMessage("tokenRevocationEndpointAuthenticationMethods cannot be empty");
	}

	@Test
	public void buildWhenTokenRevocationEndpointAuthenticationMethodsAddingOrRemovingThenCorrectValues() {
		OAuth2AuthorizationServerMetadata authorizationServerMetadata = this.minimalBuilder
			.tokenRevocationEndpointAuthenticationMethod("should-be-removed")
			.tokenRevocationEndpointAuthenticationMethods((authMethods) -> {
				authMethods.clear();
				authMethods.add("some-authentication-method");
			})
			.build();

		assertThat(authorizationServerMetadata.getTokenRevocationEndpointAuthenticationMethods())
			.containsExactly("some-authentication-method");
	}

	@Test
	public void buildWhenTokenIntrospectionEndpointNotUrlThenThrowIllegalArgumentException() {
		Builder builder = this.minimalBuilder.tokenIntrospectionEndpoint("not a valid URL");

		assertThatIllegalArgumentException().isThrownBy(builder::build)
			.withMessage("tokenIntrospectionEndpoint must be a valid URL");
	}

	@Test
	public void buildWhenTokenIntrospectionEndpointAuthenticationMethodsNotListThenThrowIllegalArgumentException() {
		Builder builder = this.minimalBuilder.claims((claims) -> claims.put(
				OAuth2AuthorizationServerMetadataClaimNames.INTROSPECTION_ENDPOINT_AUTH_METHODS_SUPPORTED,
				"not-a-list"));

		assertThatIllegalArgumentException().isThrownBy(builder::build)
			.withMessageStartingWith("tokenIntrospectionEndpointAuthenticationMethods must be of type List");
	}

	@Test
	public void buildWhenTokenIntrospectionEndpointAuthenticationMethodsEmptyListThenThrowIllegalArgumentException() {
		Builder builder = this.minimalBuilder.claims((claims) -> claims.put(
				OAuth2AuthorizationServerMetadataClaimNames.INTROSPECTION_ENDPOINT_AUTH_METHODS_SUPPORTED,
				Collections.emptyList()));

		assertThatIllegalArgumentException().isThrownBy(builder::build)
			.withMessage("tokenIntrospectionEndpointAuthenticationMethods cannot be empty");
	}

	@Test
	public void buildWhenTokenIntrospectionEndpointAuthenticationMethodsAddingOrRemovingThenCorrectValues() {
		OAuth2AuthorizationServerMetadata authorizationServerMetadata = this.minimalBuilder
			.tokenIntrospectionEndpointAuthenticationMethod("should-be-removed")
			.tokenIntrospectionEndpointAuthenticationMethods((authMethods) -> {
				authMethods.clear();
				authMethods.add("some-authentication-method");
			})
			.build();

		assertThat(authorizationServerMetadata.getTokenIntrospectionEndpointAuthenticationMethods())
			.containsExactly("some-authentication-method");
	}

	@Test
	public void buildWhenCodeChallengeMethodsNotListThenThrowIllegalArgumentException() {
		Builder builder = this.minimalBuilder.claims((claims) -> claims
			.put(OAuth2AuthorizationServerMetadataClaimNames.CODE_CHALLENGE_METHODS_SUPPORTED, "not-a-list"));

		assertThatIllegalArgumentException().isThrownBy(builder::build)
			.withMessageStartingWith("codeChallengeMethods must be of type List");
	}

	@Test
	public void buildWhenCodeChallengeMethodsEmptyListThenThrowIllegalArgumentException() {
		Builder builder = this.minimalBuilder
			.claims((claims) -> claims.put(OAuth2AuthorizationServerMetadataClaimNames.CODE_CHALLENGE_METHODS_SUPPORTED,
					Collections.emptyList()));

		assertThatIllegalArgumentException().isThrownBy(builder::build)
			.withMessage("codeChallengeMethods cannot be empty");
	}

	@Test
	public void buildWhenCodeChallengeMethodsAddingOrRemovingThenCorrectValues() {
		OAuth2AuthorizationServerMetadata authorizationServerMetadata = this.minimalBuilder
			.codeChallengeMethod("should-be-removed")
			.codeChallengeMethods((codeChallengeMethods) -> {
				codeChallengeMethods.clear();
				codeChallengeMethods.add("some-authentication-method");
			})
			.build();

		assertThat(authorizationServerMetadata.getCodeChallengeMethods()).containsExactly("some-authentication-method");
	}

	@Test
	public void buildWhenDPoPSigningAlgorithmsNotListThenThrowIllegalArgumentException() {
		Builder builder = this.minimalBuilder.claims((claims) -> claims
			.put(OAuth2AuthorizationServerMetadataClaimNames.DPOP_SIGNING_ALG_VALUES_SUPPORTED, "not-a-list"));

		assertThatIllegalArgumentException().isThrownBy(builder::build)
			.withMessageStartingWith("dPoPSigningAlgorithms must be of type List");
	}

	@Test
	public void buildWhenDPoPSigningAlgorithmsEmptyListThenThrowIllegalArgumentException() {
		Builder builder = this.minimalBuilder.claims(
				(claims) -> claims.put(OAuth2AuthorizationServerMetadataClaimNames.DPOP_SIGNING_ALG_VALUES_SUPPORTED,
						Collections.emptyList()));

		assertThatIllegalArgumentException().isThrownBy(builder::build)
			.withMessage("dPoPSigningAlgorithms cannot be empty");
	}

	@Test
	public void buildWhenDPoPSigningAlgorithmsAddingOrRemovingThenCorrectValues() {
		OAuth2AuthorizationServerMetadata authorizationServerMetadata = this.minimalBuilder
			.dPoPSigningAlgorithm(JwsAlgorithms.RS256)
			.dPoPSigningAlgorithms((algs) -> {
				algs.clear();
				algs.add(JwsAlgorithms.ES256);
			})
			.build();

		assertThat(authorizationServerMetadata.getDPoPSigningAlgorithms()).containsExactly(JwsAlgorithms.ES256);
	}

	@Test
	public void claimWhenNameNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> OAuth2AuthorizationServerMetadata.builder().claim(null, "claim-value"))
			.withMessage("name cannot be empty");
	}

	@Test
	public void claimWhenValueNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> OAuth2AuthorizationServerMetadata.builder().claim("claim-name", null))
			.withMessage("value cannot be null");
	}

	@Test
	public void claimsWhenRemovingClaimThenNotPresent() {
		OAuth2AuthorizationServerMetadata authorizationServerMetadata = this.minimalBuilder
			.claim("claim-name", "claim-value")
			.claims((claims) -> claims.remove("claim-name"))
			.build();
		assertThat(authorizationServerMetadata.hasClaim("claim-name")).isFalse();
	}

	@Test
	public void claimsWhenAddingClaimThenPresent() {
		OAuth2AuthorizationServerMetadata authorizationServerMetadata = this.minimalBuilder
			.claim("claim-name", "claim-value")
			.build();
		assertThat(authorizationServerMetadata.hasClaim("claim-name")).isTrue();
	}

	private static URL url(String urlString) {
		try {
			return new URL(urlString);
		}
		catch (Exception ex) {
			throw new IllegalArgumentException("urlString must be a valid URL and valid URI");
		}
	}

}
