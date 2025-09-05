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

package org.springframework.security.oauth2.server.authorization.oidc;

import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link OidcProviderConfiguration}.
 *
 * @author Daniel Garnier-Moiroux
 */
public class OidcProviderConfigurationTests {

	private final OidcProviderConfiguration.Builder minimalConfigurationBuilder = OidcProviderConfiguration.builder()
		.issuer("https://example.com")
		.authorizationEndpoint("https://example.com/oauth2/authorize")
		.tokenEndpoint("https://example.com/oauth2/token")
		.jwkSetUrl("https://example.com/oauth2/jwks")
		.scope("openid")
		.responseType("code")
		.subjectType("public")
		.idTokenSigningAlgorithm("RS256");

	@Test
	public void buildWhenAllRequiredClaimsAndAdditionalClaimsThenCreated() {
		OidcProviderConfiguration providerConfiguration = OidcProviderConfiguration.builder()
			.issuer("https://example.com")
			.authorizationEndpoint("https://example.com/oauth2/authorize")
			.tokenEndpoint("https://example.com/oauth2/token")
			.jwkSetUrl("https://example.com/oauth2/jwks")
			.scope("openid")
			.responseType("code")
			.grantType("authorization_code")
			.grantType("client_credentials")
			.subjectType("public")
			.idTokenSigningAlgorithm("RS256")
			.userInfoEndpoint("https://example.com/userinfo")
			.tokenEndpointAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue())
			.clientRegistrationEndpoint("https://example.com/connect/register")
			.endSessionEndpoint("https://example.com/connect/logout")
			.claim("a-claim", "a-value")
			.build();

		assertThat(providerConfiguration.getIssuer()).isEqualTo(url("https://example.com"));
		assertThat(providerConfiguration.getAuthorizationEndpoint())
			.isEqualTo(url("https://example.com/oauth2/authorize"));
		assertThat(providerConfiguration.getTokenEndpoint()).isEqualTo(url("https://example.com/oauth2/token"));
		assertThat(providerConfiguration.getJwkSetUrl()).isEqualTo(url("https://example.com/oauth2/jwks"));
		assertThat(providerConfiguration.getScopes()).containsExactly("openid");
		assertThat(providerConfiguration.getResponseTypes()).containsExactly("code");
		assertThat(providerConfiguration.getGrantTypes()).containsExactlyInAnyOrder("authorization_code",
				"client_credentials");
		assertThat(providerConfiguration.getSubjectTypes()).containsExactly("public");
		assertThat(providerConfiguration.getIdTokenSigningAlgorithms()).containsExactly("RS256");
		assertThat(providerConfiguration.getUserInfoEndpoint()).isEqualTo(url("https://example.com/userinfo"));
		assertThat(providerConfiguration.getTokenEndpointAuthenticationMethods())
			.containsExactly(ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue());
		assertThat(providerConfiguration.getClientRegistrationEndpoint())
			.isEqualTo(url("https://example.com/connect/register"));
		assertThat(providerConfiguration.getEndSessionEndpoint()).isEqualTo(url("https://example.com/connect/logout"));
		assertThat(providerConfiguration.<String>getClaim("a-claim")).isEqualTo("a-value");
	}

	@Test
	public void buildWhenOnlyRequiredClaimsThenCreated() {
		OidcProviderConfiguration providerConfiguration = OidcProviderConfiguration.builder()
			.issuer("https://example.com")
			.authorizationEndpoint("https://example.com/oauth2/authorize")
			.tokenEndpoint("https://example.com/oauth2/token")
			.jwkSetUrl("https://example.com/oauth2/jwks")
			.scope("openid")
			.responseType("code")
			.subjectType("public")
			.idTokenSigningAlgorithm("RS256")
			.build();

		assertThat(providerConfiguration.getIssuer()).isEqualTo(url("https://example.com"));
		assertThat(providerConfiguration.getAuthorizationEndpoint())
			.isEqualTo(url("https://example.com/oauth2/authorize"));
		assertThat(providerConfiguration.getTokenEndpoint()).isEqualTo(url("https://example.com/oauth2/token"));
		assertThat(providerConfiguration.getJwkSetUrl()).isEqualTo(url("https://example.com/oauth2/jwks"));
		assertThat(providerConfiguration.getScopes()).containsExactly("openid");
		assertThat(providerConfiguration.getResponseTypes()).containsExactly("code");
		assertThat(providerConfiguration.getGrantTypes()).isNull();
		assertThat(providerConfiguration.getSubjectTypes()).containsExactly("public");
		assertThat(providerConfiguration.getIdTokenSigningAlgorithms()).containsExactly("RS256");
		assertThat(providerConfiguration.getTokenEndpointAuthenticationMethods()).isNull();
	}

	@Test
	public void buildWhenClaimsProvidedThenCreated() {
		Map<String, Object> claims = new HashMap<>();
		claims.put(OidcProviderMetadataClaimNames.ISSUER, "https://example.com");
		claims.put(OidcProviderMetadataClaimNames.AUTHORIZATION_ENDPOINT, "https://example.com/oauth2/authorize");
		claims.put(OidcProviderMetadataClaimNames.TOKEN_ENDPOINT, "https://example.com/oauth2/token");
		claims.put(OidcProviderMetadataClaimNames.JWKS_URI, "https://example.com/oauth2/jwks");
		claims.put(OidcProviderMetadataClaimNames.SCOPES_SUPPORTED, Collections.singletonList("openid"));
		claims.put(OidcProviderMetadataClaimNames.RESPONSE_TYPES_SUPPORTED, Collections.singletonList("code"));
		claims.put(OidcProviderMetadataClaimNames.SUBJECT_TYPES_SUPPORTED, Collections.singletonList("public"));
		claims.put(OidcProviderMetadataClaimNames.ID_TOKEN_SIGNING_ALG_VALUES_SUPPORTED,
				Collections.singletonList("RS256"));
		claims.put(OidcProviderMetadataClaimNames.USER_INFO_ENDPOINT, "https://example.com/userinfo");
		claims.put(OidcProviderMetadataClaimNames.REGISTRATION_ENDPOINT, "https://example.com/connect/register");
		claims.put(OidcProviderMetadataClaimNames.END_SESSION_ENDPOINT, "https://example.com/connect/logout");
		claims.put("some-claim", "some-value");

		OidcProviderConfiguration providerConfiguration = OidcProviderConfiguration.withClaims(claims).build();

		assertThat(providerConfiguration.getIssuer()).isEqualTo(url("https://example.com"));
		assertThat(providerConfiguration.getAuthorizationEndpoint())
			.isEqualTo(url("https://example.com/oauth2/authorize"));
		assertThat(providerConfiguration.getTokenEndpoint()).isEqualTo(url("https://example.com/oauth2/token"));
		assertThat(providerConfiguration.getJwkSetUrl()).isEqualTo(url("https://example.com/oauth2/jwks"));
		assertThat(providerConfiguration.getScopes()).containsExactly("openid");
		assertThat(providerConfiguration.getResponseTypes()).containsExactly("code");
		assertThat(providerConfiguration.getGrantTypes()).isNull();
		assertThat(providerConfiguration.getSubjectTypes()).containsExactly("public");
		assertThat(providerConfiguration.getIdTokenSigningAlgorithms()).containsExactly("RS256");
		assertThat(providerConfiguration.getUserInfoEndpoint()).isEqualTo(url("https://example.com/userinfo"));
		assertThat(providerConfiguration.getTokenEndpointAuthenticationMethods()).isNull();
		assertThat(providerConfiguration.getClientRegistrationEndpoint())
			.isEqualTo(url("https://example.com/connect/register"));
		assertThat(providerConfiguration.getEndSessionEndpoint()).isEqualTo(url("https://example.com/connect/logout"));
		assertThat(providerConfiguration.<String>getClaim("some-claim")).isEqualTo("some-value");
	}

	@Test
	public void buildWhenClaimsProvidedWithUrlsThenCreated() {
		Map<String, Object> claims = new HashMap<>();
		claims.put(OidcProviderMetadataClaimNames.ISSUER, url("https://example.com"));
		claims.put(OidcProviderMetadataClaimNames.AUTHORIZATION_ENDPOINT, url("https://example.com/oauth2/authorize"));
		claims.put(OidcProviderMetadataClaimNames.TOKEN_ENDPOINT, url("https://example.com/oauth2/token"));
		claims.put(OidcProviderMetadataClaimNames.JWKS_URI, url("https://example.com/oauth2/jwks"));
		claims.put(OidcProviderMetadataClaimNames.SCOPES_SUPPORTED, Collections.singletonList("openid"));
		claims.put(OidcProviderMetadataClaimNames.RESPONSE_TYPES_SUPPORTED, Collections.singletonList("code"));
		claims.put(OidcProviderMetadataClaimNames.SUBJECT_TYPES_SUPPORTED, Collections.singletonList("public"));
		claims.put(OidcProviderMetadataClaimNames.ID_TOKEN_SIGNING_ALG_VALUES_SUPPORTED,
				Collections.singletonList("RS256"));
		claims.put(OidcProviderMetadataClaimNames.USER_INFO_ENDPOINT, url("https://example.com/userinfo"));
		claims.put(OidcProviderMetadataClaimNames.REGISTRATION_ENDPOINT, url("https://example.com/connect/register"));
		claims.put(OidcProviderMetadataClaimNames.END_SESSION_ENDPOINT, url("https://example.com/connect/logout"));
		claims.put("some-claim", "some-value");

		OidcProviderConfiguration providerConfiguration = OidcProviderConfiguration.withClaims(claims).build();

		assertThat(providerConfiguration.getIssuer()).isEqualTo(url("https://example.com"));
		assertThat(providerConfiguration.getAuthorizationEndpoint())
			.isEqualTo(url("https://example.com/oauth2/authorize"));
		assertThat(providerConfiguration.getTokenEndpoint()).isEqualTo(url("https://example.com/oauth2/token"));
		assertThat(providerConfiguration.getJwkSetUrl()).isEqualTo(url("https://example.com/oauth2/jwks"));
		assertThat(providerConfiguration.getScopes()).containsExactly("openid");
		assertThat(providerConfiguration.getResponseTypes()).containsExactly("code");
		assertThat(providerConfiguration.getGrantTypes()).isNull();
		assertThat(providerConfiguration.getSubjectTypes()).containsExactly("public");
		assertThat(providerConfiguration.getIdTokenSigningAlgorithms()).containsExactly("RS256");
		assertThat(providerConfiguration.getUserInfoEndpoint()).isEqualTo(url("https://example.com/userinfo"));
		assertThat(providerConfiguration.getTokenEndpointAuthenticationMethods()).isNull();
		assertThat(providerConfiguration.getClientRegistrationEndpoint())
			.isEqualTo(url("https://example.com/connect/register"));
		assertThat(providerConfiguration.getEndSessionEndpoint()).isEqualTo(url("https://example.com/connect/logout"));
		assertThat(providerConfiguration.<String>getClaim("some-claim")).isEqualTo("some-value");
	}

	@Test
	public void withClaimsWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> OidcProviderConfiguration.withClaims(null))
			.isInstanceOf(IllegalArgumentException.class)
			.withMessage("claims cannot be empty");
	}

	@Test
	public void withClaimsWhenMissingRequiredClaimsThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> OidcProviderConfiguration.withClaims(Collections.emptyMap()))
			.withMessage("claims cannot be empty");
	}

	@Test
	public void buildWhenCalledTwiceThenGeneratesTwoConfigurations() {
		OidcProviderConfiguration first = this.minimalConfigurationBuilder.grantType("client_credentials").build();

		OidcProviderConfiguration second = this.minimalConfigurationBuilder.claims((claims) -> {
			List<String> newGrantTypes = new ArrayList<>();
			newGrantTypes.add("authorization_code");
			newGrantTypes.add("custom_grant");
			claims.put(OidcProviderMetadataClaimNames.GRANT_TYPES_SUPPORTED, newGrantTypes);
		}).build();

		assertThat(first.getGrantTypes()).containsExactly("client_credentials");
		assertThat(second.getGrantTypes()).containsExactlyInAnyOrder("authorization_code", "custom_grant");
	}

	@Test
	public void buildWhenMissingIssuerThenThrowIllegalArgumentException() {
		OidcProviderConfiguration.Builder builder = this.minimalConfigurationBuilder
			.claims((claims) -> claims.remove(OidcProviderMetadataClaimNames.ISSUER));

		assertThatIllegalArgumentException().isThrownBy(builder::build).withMessage("issuer cannot be null");
	}

	@Test
	public void buildWhenIssuerNotUrlThenThrowIllegalArgumentException() {
		OidcProviderConfiguration.Builder builder = this.minimalConfigurationBuilder
			.claims((claims) -> claims.put(OidcProviderMetadataClaimNames.ISSUER, "not an url"));

		assertThatIllegalArgumentException().isThrownBy(builder::build).withMessage("issuer must be a valid URL");
	}

	@Test
	public void buildWhenMissingAuthorizationEndpointThenThrowIllegalArgumentException() {
		OidcProviderConfiguration.Builder builder = this.minimalConfigurationBuilder
			.claims((claims) -> claims.remove(OidcProviderMetadataClaimNames.AUTHORIZATION_ENDPOINT));

		assertThatIllegalArgumentException().isThrownBy(builder::build)
			.withMessage("authorizationEndpoint cannot be null");
	}

	@Test
	public void buildWhenAuthorizationEndpointNotUrlThenThrowIllegalArgumentException() {
		OidcProviderConfiguration.Builder builder = this.minimalConfigurationBuilder
			.claims((claims) -> claims.put(OidcProviderMetadataClaimNames.AUTHORIZATION_ENDPOINT, "not an url"));

		assertThatIllegalArgumentException().isThrownBy(builder::build)
			.withMessageStartingWith("authorizationEndpoint must be a valid URL");
	}

	@Test
	public void buildWhenMissingTokenEndpointThenThrowIllegalArgumentException() {
		OidcProviderConfiguration.Builder builder = this.minimalConfigurationBuilder
			.claims((claims) -> claims.remove(OidcProviderMetadataClaimNames.TOKEN_ENDPOINT));

		assertThatIllegalArgumentException().isThrownBy(builder::build).withMessage("tokenEndpoint cannot be null");
	}

	@Test
	public void buildWhenTokenEndpointNotUrlThenThrowIllegalArgumentException() {
		OidcProviderConfiguration.Builder builder = this.minimalConfigurationBuilder
			.claims((claims) -> claims.put(OidcProviderMetadataClaimNames.TOKEN_ENDPOINT, "not an url"));

		assertThatIllegalArgumentException().isThrownBy(builder::build)
			.withMessageStartingWith("tokenEndpoint must be a valid URL");
	}

	@Test
	public void buildWhenMissingJwksUriThenThrowIllegalArgumentException() {
		OidcProviderConfiguration.Builder builder = this.minimalConfigurationBuilder
			.claims((claims) -> claims.remove(OidcProviderMetadataClaimNames.JWKS_URI));

		assertThatIllegalArgumentException().isThrownBy(builder::build).withMessage("jwksUri cannot be null");
	}

	@Test
	public void buildWhenJwksUriNotUrlThenThrowIllegalArgumentException() {
		OidcProviderConfiguration.Builder builder = this.minimalConfigurationBuilder
			.claims((claims) -> claims.put(OidcProviderMetadataClaimNames.JWKS_URI, "not an url"));

		assertThatIllegalArgumentException().isThrownBy(builder::build)
			.withMessageStartingWith("jwksUri must be a valid URL");
	}

	@Test
	public void buildWhenMissingResponseTypesThenThrowIllegalArgumentException() {
		OidcProviderConfiguration.Builder builder = this.minimalConfigurationBuilder
			.claims((claims) -> claims.remove(OidcProviderMetadataClaimNames.RESPONSE_TYPES_SUPPORTED));

		assertThatIllegalArgumentException().isThrownBy(builder::build).withMessage("responseTypes cannot be null");
	}

	@Test
	public void buildWhenResponseTypesNotListThenThrowIllegalArgumentException() {
		OidcProviderConfiguration.Builder builder = this.minimalConfigurationBuilder.claims((claims) -> {
			claims.remove(OidcProviderMetadataClaimNames.RESPONSE_TYPES_SUPPORTED);
			claims.put(OidcProviderMetadataClaimNames.RESPONSE_TYPES_SUPPORTED, "code");
		});

		assertThatIllegalArgumentException().isThrownBy(builder::build)
			.withMessageContaining("responseTypes must be of type List");
	}

	@Test
	public void buildWhenResponseTypesEmptyListThenThrowIllegalArgumentException() {
		OidcProviderConfiguration.Builder builder = this.minimalConfigurationBuilder.claims((claims) -> {
			claims.remove(OidcProviderMetadataClaimNames.RESPONSE_TYPES_SUPPORTED);
			claims.put(OidcProviderMetadataClaimNames.RESPONSE_TYPES_SUPPORTED, Collections.emptyList());
		});

		assertThatIllegalArgumentException().isThrownBy(builder::build)
			.withMessageContaining("responseTypes cannot be empty");
	}

	@Test
	public void buildWhenMissingSubjectTypesThenThrowIllegalArgumentException() {
		OidcProviderConfiguration.Builder builder = this.minimalConfigurationBuilder
			.claims((claims) -> claims.remove(OidcProviderMetadataClaimNames.SUBJECT_TYPES_SUPPORTED));

		assertThatIllegalArgumentException().isThrownBy(builder::build).withMessage("subjectTypes cannot be null");
	}

	@Test
	public void buildWhenSubjectTypesNotListThenThrowIllegalArgumentException() {
		OidcProviderConfiguration.Builder builder = this.minimalConfigurationBuilder.claims((claims) -> {
			claims.remove(OidcProviderMetadataClaimNames.SUBJECT_TYPES_SUPPORTED);
			claims.put(OidcProviderMetadataClaimNames.SUBJECT_TYPES_SUPPORTED, "public");
		});

		assertThatIllegalArgumentException().isThrownBy(builder::build)
			.withMessageContaining("subjectTypes must be of type List");
	}

	@Test
	public void buildWhenSubjectTypesEmptyListThenThrowIllegalArgumentException() {
		OidcProviderConfiguration.Builder builder = this.minimalConfigurationBuilder.claims((claims) -> {
			claims.remove(OidcProviderMetadataClaimNames.SUBJECT_TYPES_SUPPORTED);
			claims.put(OidcProviderMetadataClaimNames.SUBJECT_TYPES_SUPPORTED, Collections.emptyList());
		});

		assertThatIllegalArgumentException().isThrownBy(builder::build)
			.withMessageContaining("subjectTypes cannot be empty");
	}

	@Test
	public void buildWhenMissingIdTokenSigningAlgorithmsThenThrowIllegalArgumentException() {
		OidcProviderConfiguration.Builder builder = this.minimalConfigurationBuilder
			.claims((claims) -> claims.remove(OidcProviderMetadataClaimNames.ID_TOKEN_SIGNING_ALG_VALUES_SUPPORTED));

		assertThatIllegalArgumentException().isThrownBy(builder::build)
			.withMessage("idTokenSigningAlgorithms cannot be null");
	}

	@Test
	public void buildWhenIdTokenSigningAlgorithmsNotListThenThrowIllegalArgumentException() {
		OidcProviderConfiguration.Builder builder = this.minimalConfigurationBuilder.claims((claims) -> {
			claims.remove(OidcProviderMetadataClaimNames.ID_TOKEN_SIGNING_ALG_VALUES_SUPPORTED);
			claims.put(OidcProviderMetadataClaimNames.ID_TOKEN_SIGNING_ALG_VALUES_SUPPORTED, "RS256");
		});

		assertThatIllegalArgumentException().isThrownBy(builder::build)
			.withMessageContaining("idTokenSigningAlgorithms must be of type List");
	}

	@Test
	public void buildWhenIdTokenSigningAlgorithmsEmptyListThenThrowIllegalArgumentException() {
		OidcProviderConfiguration.Builder builder = this.minimalConfigurationBuilder.claims((claims) -> {
			claims.remove(OidcProviderMetadataClaimNames.ID_TOKEN_SIGNING_ALG_VALUES_SUPPORTED);
			claims.put(OidcProviderMetadataClaimNames.ID_TOKEN_SIGNING_ALG_VALUES_SUPPORTED, Collections.emptyList());
		});

		assertThatIllegalArgumentException().isThrownBy(builder::build)
			.withMessageContaining("idTokenSigningAlgorithms cannot be empty");
	}

	@Test
	public void buildWhenUserInfoEndpointNotUrlThenThrowIllegalArgumentException() {
		OidcProviderConfiguration.Builder builder = this.minimalConfigurationBuilder
			.claims((claims) -> claims.put(OidcProviderMetadataClaimNames.USER_INFO_ENDPOINT, "not an url"));

		assertThatIllegalArgumentException().isThrownBy(builder::build)
			.withMessage("userInfoEndpoint must be a valid URL");
	}

	@Test
	public void buildWhenClientRegistrationEndpointNotUrlThenThrowIllegalArgumentException() {
		OidcProviderConfiguration.Builder builder = this.minimalConfigurationBuilder
			.claims((claims) -> claims.put(OidcProviderMetadataClaimNames.REGISTRATION_ENDPOINT, "not an url"));

		assertThatIllegalArgumentException().isThrownBy(builder::build)
			.withMessage("clientRegistrationEndpoint must be a valid URL");
	}

	@Test
	public void buildWhenEndSessionEndpointNotUrlThenThrowIllegalArgumentException() {
		OidcProviderConfiguration.Builder builder = this.minimalConfigurationBuilder
			.claims((claims) -> claims.put(OidcProviderMetadataClaimNames.END_SESSION_ENDPOINT, "not an url"));

		assertThatIllegalArgumentException().isThrownBy(builder::build)
			.withMessage("endSessionEndpoint must be a valid URL");
	}

	@Test
	public void responseTypesWhenAddingOrRemovingThenCorrectValues() {
		OidcProviderConfiguration configuration = this.minimalConfigurationBuilder.responseType("should-be-removed")
			.responseTypes((responseTypes) -> {
				responseTypes.clear();
				responseTypes.add("some-response-type");
			})
			.build();

		assertThat(configuration.getResponseTypes()).containsExactly("some-response-type");
	}

	@Test
	public void responseTypesWhenNotPresentAndAddingThenCorrectValues() {
		OidcProviderConfiguration configuration = this.minimalConfigurationBuilder
			.claims((claims) -> claims.remove(OidcProviderMetadataClaimNames.RESPONSE_TYPES_SUPPORTED))
			.responseTypes((responseTypes) -> responseTypes.add("some-response-type"))
			.build();

		assertThat(configuration.getResponseTypes()).containsExactly("some-response-type");
	}

	@Test
	public void subjectTypesWhenAddingOrRemovingThenCorrectValues() {
		OidcProviderConfiguration configuration = this.minimalConfigurationBuilder.subjectType("should-be-removed")
			.subjectTypes((subjectTypes) -> {
				subjectTypes.clear();
				subjectTypes.add("some-subject-type");
			})
			.build();

		assertThat(configuration.getSubjectTypes()).containsExactly("some-subject-type");
	}

	@Test
	public void idTokenSigningAlgorithmsWhenAddingOrRemovingThenCorrectValues() {
		OidcProviderConfiguration configuration = this.minimalConfigurationBuilder
			.idTokenSigningAlgorithm("should-be-removed")
			.idTokenSigningAlgorithms((signingAlgorithms) -> {
				signingAlgorithms.clear();
				signingAlgorithms.add("ES256");
			})
			.build();

		assertThat(configuration.getIdTokenSigningAlgorithms()).containsExactly("ES256");
	}

	@Test
	public void scopesWhenAddingOrRemovingThenCorrectValues() {
		OidcProviderConfiguration configuration = this.minimalConfigurationBuilder.scope("should-be-removed")
			.scopes((scopes) -> {
				scopes.clear();
				scopes.add("some-scope");
			})
			.build();

		assertThat(configuration.getScopes()).containsExactly("some-scope");
	}

	@Test
	public void grantTypesWhenAddingOrRemovingThenCorrectValues() {
		OidcProviderConfiguration configuration = this.minimalConfigurationBuilder.grantType("should-be-removed")
			.grantTypes((grantTypes) -> {
				grantTypes.clear();
				grantTypes.add("some-grant-type");
			})
			.build();

		assertThat(configuration.getGrantTypes()).containsExactly("some-grant-type");
	}

	@Test
	public void tokenEndpointAuthenticationMethodsWhenAddingOrRemovingThenCorrectValues() {
		OidcProviderConfiguration configuration = this.minimalConfigurationBuilder
			.tokenEndpointAuthenticationMethod("should-be-removed")
			.tokenEndpointAuthenticationMethods((authMethods) -> {
				authMethods.clear();
				authMethods.add("some-authentication-method");
			})
			.build();

		assertThat(configuration.getTokenEndpointAuthenticationMethods()).containsExactly("some-authentication-method");
	}

	@Test
	public void claimWhenNameIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> OidcProviderConfiguration.builder().claim(null, "value"))
			.withMessage("name cannot be empty");
	}

	@Test
	public void claimWhenValueIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> OidcProviderConfiguration.builder().claim("claim-name", null))
			.withMessage("value cannot be null");
	}

	@Test
	public void claimsWhenRemovingClaimThenNotPresent() {
		OidcProviderConfiguration configuration = this.minimalConfigurationBuilder.grantType("some-grant-type")
			.claims((claims) -> claims.remove(OidcProviderMetadataClaimNames.GRANT_TYPES_SUPPORTED))
			.build();
		assertThat(configuration.getGrantTypes()).isNull();
	}

	@Test
	public void claimsWhenAddingClaimThenPresent() {
		OidcProviderConfiguration configuration = this.minimalConfigurationBuilder.claim("claim-name", "claim-value")
			.build();
		assertThat(configuration.hasClaim("claim-name")).isTrue();
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
