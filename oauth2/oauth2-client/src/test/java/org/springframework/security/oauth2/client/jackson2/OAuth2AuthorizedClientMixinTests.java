/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.oauth2.client.jackson2;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.DecimalUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.skyscreamer.jsonassert.JSONAssert;

import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.TestOAuth2AccessTokens;
import org.springframework.security.oauth2.core.TestOAuth2RefreshTokens;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * Tests for {@link OAuth2AuthorizedClientMixin}.
 *
 * @author Joe Grandja
 */
public class OAuth2AuthorizedClientMixinTests {

	private ObjectMapper mapper;

	private ClientRegistration.Builder clientRegistrationBuilder;

	private OAuth2AccessToken accessToken;

	private OAuth2RefreshToken refreshToken;

	private String principalName;

	@BeforeEach
	public void setup() {
		ClassLoader loader = getClass().getClassLoader();
		this.mapper = new ObjectMapper();
		this.mapper.registerModules(SecurityJackson2Modules.getModules(loader));
		Map<String, Object> providerConfigurationMetadata = new LinkedHashMap<>();
		providerConfigurationMetadata.put("config1", "value1");
		providerConfigurationMetadata.put("config2", "value2");
		// @formatter:off
		this.clientRegistrationBuilder = TestClientRegistrations.clientRegistration()
				.authorizationGrantType(new AuthorizationGrantType("custom-grant"))
				.scope("read", "write")
				.providerConfigurationMetadata(providerConfigurationMetadata);
		// @formatter:on
		this.accessToken = TestOAuth2AccessTokens.scopes("read", "write");
		this.refreshToken = TestOAuth2RefreshTokens.refreshToken();
		this.principalName = "principal-name";
	}

	@Test
	public void serializeWhenMixinRegisteredThenSerializes() throws Exception {
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.clientRegistrationBuilder.build(),
				this.principalName, this.accessToken, this.refreshToken);
		String expectedJson = asJson(authorizedClient);
		String json = this.mapper.writeValueAsString(authorizedClient);
		JSONAssert.assertEquals(expectedJson, json, true);
	}

	@Test
	public void serializeWhenRequiredAttributesOnlyThenSerializes() throws Exception {
		// @formatter:off
		ClientRegistration clientRegistration = TestClientRegistrations.clientRegistration()
				.clientSecret(null)
				.clientName(null)
				.userInfoUri(null)
				.userNameAttributeName(null)
				.jwkSetUri(null)
				.issuerUri(null)
				.build();
		// @formatter:on
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(clientRegistration, this.principalName,
				TestOAuth2AccessTokens.noScopes());
		String expectedJson = asJson(authorizedClient);
		String json = this.mapper.writeValueAsString(authorizedClient);
		JSONAssert.assertEquals(expectedJson, json, true);
	}

	@Test
	public void deserializeWhenMixinNotRegisteredThenThrowJsonProcessingException() {
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.clientRegistrationBuilder.build(),
				this.principalName, this.accessToken);
		String json = asJson(authorizedClient);
		assertThatExceptionOfType(JsonProcessingException.class)
			.isThrownBy(() -> new ObjectMapper().readValue(json, OAuth2AuthorizedClient.class));
	}

	@Test
	public void deserializeWhenMixinRegisteredThenDeserializes() throws Exception {
		ClientRegistration expectedClientRegistration = this.clientRegistrationBuilder.build();
		OAuth2AccessToken expectedAccessToken = this.accessToken;
		OAuth2RefreshToken expectedRefreshToken = this.refreshToken;
		OAuth2AuthorizedClient expectedAuthorizedClient = new OAuth2AuthorizedClient(expectedClientRegistration,
				this.principalName, expectedAccessToken, expectedRefreshToken);
		String json = asJson(expectedAuthorizedClient);
		OAuth2AuthorizedClient authorizedClient = this.mapper.readValue(json, OAuth2AuthorizedClient.class);
		ClientRegistration clientRegistration = authorizedClient.getClientRegistration();
		assertThat(clientRegistration.getRegistrationId()).isEqualTo(expectedClientRegistration.getRegistrationId());
		assertThat(clientRegistration.getClientId()).isEqualTo(expectedClientRegistration.getClientId());
		assertThat(clientRegistration.getClientSecret()).isEqualTo(expectedClientRegistration.getClientSecret());
		assertThat(clientRegistration.getClientAuthenticationMethod())
			.isEqualTo(expectedClientRegistration.getClientAuthenticationMethod());
		assertThat(clientRegistration.getAuthorizationGrantType())
			.isEqualTo(expectedClientRegistration.getAuthorizationGrantType());
		assertThat(clientRegistration.getRedirectUri()).isEqualTo(expectedClientRegistration.getRedirectUri());
		assertThat(clientRegistration.getScopes()).isEqualTo(expectedClientRegistration.getScopes());
		assertThat(clientRegistration.getProviderDetails().getAuthorizationUri())
			.isEqualTo(expectedClientRegistration.getProviderDetails().getAuthorizationUri());
		assertThat(clientRegistration.getProviderDetails().getTokenUri())
			.isEqualTo(expectedClientRegistration.getProviderDetails().getTokenUri());
		assertThat(clientRegistration.getProviderDetails().getUserInfoEndpoint().getUri())
			.isEqualTo(expectedClientRegistration.getProviderDetails().getUserInfoEndpoint().getUri());
		assertThat(clientRegistration.getProviderDetails().getUserInfoEndpoint().getAuthenticationMethod())
			.isEqualTo(expectedClientRegistration.getProviderDetails().getUserInfoEndpoint().getAuthenticationMethod());
		assertThat(clientRegistration.getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName()).isEqualTo(
				expectedClientRegistration.getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName());
		assertThat(clientRegistration.getProviderDetails().getJwkSetUri())
			.isEqualTo(expectedClientRegistration.getProviderDetails().getJwkSetUri());
		assertThat(clientRegistration.getProviderDetails().getIssuerUri())
			.isEqualTo(expectedClientRegistration.getProviderDetails().getIssuerUri());
		assertThat(clientRegistration.getProviderDetails().getConfigurationMetadata())
			.containsExactlyEntriesOf(clientRegistration.getProviderDetails().getConfigurationMetadata());
		assertThat(clientRegistration.getClientName()).isEqualTo(expectedClientRegistration.getClientName());
		assertThat(authorizedClient.getPrincipalName()).isEqualTo(expectedAuthorizedClient.getPrincipalName());
		OAuth2AccessToken accessToken = authorizedClient.getAccessToken();
		assertThat(accessToken.getTokenType()).isEqualTo(expectedAccessToken.getTokenType());
		assertThat(accessToken.getScopes()).isEqualTo(expectedAccessToken.getScopes());
		assertThat(accessToken.getTokenValue()).isEqualTo(expectedAccessToken.getTokenValue());
		assertThat(accessToken.getIssuedAt()).isEqualTo(expectedAccessToken.getIssuedAt());
		assertThat(accessToken.getExpiresAt()).isEqualTo(expectedAccessToken.getExpiresAt());
		OAuth2RefreshToken refreshToken = authorizedClient.getRefreshToken();
		assertThat(refreshToken.getTokenValue()).isEqualTo(expectedRefreshToken.getTokenValue());
		assertThat(refreshToken.getIssuedAt()).isEqualTo(expectedRefreshToken.getIssuedAt());
		assertThat(refreshToken.getExpiresAt()).isEqualTo(expectedRefreshToken.getExpiresAt());
	}

	@Test
	public void deserializeWhenRequiredAttributesOnlyThenDeserializes() throws Exception {
		// @formatter:off
		ClientRegistration expectedClientRegistration = TestClientRegistrations.clientRegistration()
				.clientSecret(null)
				.clientName(null)
				.userInfoUri(null)
				.userNameAttributeName(null)
				.jwkSetUri(null)
				.issuerUri(null)
				.build();
		// @formatter:on
		OAuth2AccessToken expectedAccessToken = TestOAuth2AccessTokens.noScopes();
		OAuth2AuthorizedClient expectedAuthorizedClient = new OAuth2AuthorizedClient(expectedClientRegistration,
				this.principalName, expectedAccessToken);
		String json = asJson(expectedAuthorizedClient);
		OAuth2AuthorizedClient authorizedClient = this.mapper.readValue(json, OAuth2AuthorizedClient.class);
		ClientRegistration clientRegistration = authorizedClient.getClientRegistration();
		assertThat(clientRegistration.getRegistrationId()).isEqualTo(expectedClientRegistration.getRegistrationId());
		assertThat(clientRegistration.getClientId()).isEqualTo(expectedClientRegistration.getClientId());
		assertThat(clientRegistration.getClientSecret()).isEmpty();
		assertThat(clientRegistration.getClientAuthenticationMethod())
			.isEqualTo(expectedClientRegistration.getClientAuthenticationMethod());
		assertThat(clientRegistration.getAuthorizationGrantType())
			.isEqualTo(expectedClientRegistration.getAuthorizationGrantType());
		assertThat(clientRegistration.getRedirectUri()).isEqualTo(expectedClientRegistration.getRedirectUri());
		assertThat(clientRegistration.getScopes()).isEqualTo(expectedClientRegistration.getScopes());
		assertThat(clientRegistration.getProviderDetails().getAuthorizationUri())
			.isEqualTo(expectedClientRegistration.getProviderDetails().getAuthorizationUri());
		assertThat(clientRegistration.getProviderDetails().getTokenUri())
			.isEqualTo(expectedClientRegistration.getProviderDetails().getTokenUri());
		assertThat(clientRegistration.getProviderDetails().getUserInfoEndpoint().getUri()).isNull();
		assertThat(clientRegistration.getProviderDetails().getUserInfoEndpoint().getAuthenticationMethod())
			.isEqualTo(expectedClientRegistration.getProviderDetails().getUserInfoEndpoint().getAuthenticationMethod());
		assertThat(clientRegistration.getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName()).isNull();
		assertThat(clientRegistration.getProviderDetails().getJwkSetUri()).isNull();
		assertThat(clientRegistration.getProviderDetails().getIssuerUri()).isNull();
		assertThat(clientRegistration.getProviderDetails().getConfigurationMetadata()).isEmpty();
		assertThat(clientRegistration.getClientName()).isEqualTo(clientRegistration.getRegistrationId());
		assertThat(authorizedClient.getPrincipalName()).isEqualTo(expectedAuthorizedClient.getPrincipalName());
		OAuth2AccessToken accessToken = authorizedClient.getAccessToken();
		assertThat(accessToken.getTokenType()).isEqualTo(expectedAccessToken.getTokenType());
		assertThat(accessToken.getScopes()).isEmpty();
		assertThat(accessToken.getTokenValue()).isEqualTo(expectedAccessToken.getTokenValue());
		assertThat(accessToken.getIssuedAt()).isEqualTo(expectedAccessToken.getIssuedAt());
		assertThat(accessToken.getExpiresAt()).isEqualTo(expectedAccessToken.getExpiresAt());
		assertThat(authorizedClient.getRefreshToken()).isNull();
	}

	@Test
	void deserializeWhenClientSettingsPropertyDoesNotExistThenDefaulted() throws JsonProcessingException {
		// ClientRegistration.clientSettings was added later, so old values will be
		// serialized without that property
		// this test checks for passivity
		ClientRegistration clientRegistration = this.clientRegistrationBuilder.build();
		ClientRegistration.ProviderDetails providerDetails = clientRegistration.getProviderDetails();
		ClientRegistration.ProviderDetails.UserInfoEndpoint userInfoEndpoint = providerDetails.getUserInfoEndpoint();
		String scopes = "";
		if (!CollectionUtils.isEmpty(clientRegistration.getScopes())) {
			scopes = StringUtils.collectionToDelimitedString(clientRegistration.getScopes(), ",", "\"", "\"");
		}
		String configurationMetadata = "\"@class\": \"java.util.Collections$UnmodifiableMap\"";
		if (!CollectionUtils.isEmpty(providerDetails.getConfigurationMetadata())) {
			configurationMetadata += "," + providerDetails.getConfigurationMetadata()
				.keySet()
				.stream()
				.map((key) -> "\"" + key + "\": \"" + providerDetails.getConfigurationMetadata().get(key) + "\"")
				.collect(Collectors.joining(","));
		}
		// @formatter:off
		String json = "{\n" +
				"    \"@class\": \"org.springframework.security.oauth2.client.registration.ClientRegistration\",\n" +
				"    \"registrationId\": \"" + clientRegistration.getRegistrationId() + "\",\n" +
				"    \"clientId\": \"" + clientRegistration.getClientId() + "\",\n" +
				"    \"clientSecret\": \"" + clientRegistration.getClientSecret() + "\",\n" +
				"    \"clientAuthenticationMethod\": {\n" +
				"      \"value\": \"" + clientRegistration.getClientAuthenticationMethod().getValue() + "\"\n" +
				"    },\n" +
				"    \"authorizationGrantType\": {\n" +
				"      \"value\": \"" + clientRegistration.getAuthorizationGrantType().getValue() + "\"\n" +
				"    },\n" +
				"    \"redirectUri\": \"" + clientRegistration.getRedirectUri() + "\",\n" +
				"    \"scopes\": [\n" +
				"      \"java.util.Collections$UnmodifiableSet\",\n" +
				"      [" + scopes + "]\n" +
				"    ],\n" +
				"    \"providerDetails\": {\n" +
				"      \"@class\": \"org.springframework.security.oauth2.client.registration.ClientRegistration$ProviderDetails\",\n" +
				"      \"authorizationUri\": \"" + providerDetails.getAuthorizationUri() + "\",\n" +
				"      \"tokenUri\": \"" + providerDetails.getTokenUri() + "\",\n" +
				"      \"userInfoEndpoint\": {\n" +
				"        \"@class\": \"org.springframework.security.oauth2.client.registration.ClientRegistration$ProviderDetails$UserInfoEndpoint\",\n" +
				"        \"uri\": " + ((userInfoEndpoint.getUri() != null) ? "\"" + userInfoEndpoint.getUri() + "\"" : null) + ",\n" +
				"        \"authenticationMethod\": {\n" +
				"          \"value\": \"" + userInfoEndpoint.getAuthenticationMethod().getValue() + "\"\n" +
				"        },\n" +
				"        \"userNameAttributeName\": " + ((userInfoEndpoint.getUserNameAttributeName() != null) ? "\"" + userInfoEndpoint.getUserNameAttributeName() + "\"" : null) + "\n" +
				"      },\n" +
				"      \"jwkSetUri\": " + ((providerDetails.getJwkSetUri() != null) ? "\"" + providerDetails.getJwkSetUri() + "\"" : null) + ",\n" +
				"      \"issuerUri\": " + ((providerDetails.getIssuerUri() != null) ? "\"" + providerDetails.getIssuerUri() + "\"" : null) + ",\n" +
				"      \"configurationMetadata\": {\n" +
				"        " + configurationMetadata + "\n" +
				"      }\n" +
				"    },\n" +
				"    \"clientName\": \"" + clientRegistration.getClientName() + "\"\n" +
				"}";
		// @formatter:on
		// validate the test input
		assertThat(json).doesNotContain("clientSettings");
		ClientRegistration registration = this.mapper.readValue(json, ClientRegistration.class);
		// the default value of requireProofKey is false
		assertThat(registration.getClientSettings().isRequireProofKey()).isFalse();
	}

	private static String asJson(OAuth2AuthorizedClient authorizedClient) {
		// @formatter:off
		return "{\n" +
				"  \"@class\": \"org.springframework.security.oauth2.client.OAuth2AuthorizedClient\",\n" +
				"  \"clientRegistration\": " + asJson(authorizedClient.getClientRegistration()) + ",\n" +
				"  \"principalName\": \"" + authorizedClient.getPrincipalName() + "\",\n" +
				"  \"accessToken\": " + asJson(authorizedClient.getAccessToken()) + ",\n" +
				"  \"refreshToken\": " + asJson(authorizedClient.getRefreshToken()) + "\n" +
				"}";
		// @formatter:on
	}

	private static String asJson(ClientRegistration clientRegistration) {
		ClientRegistration.ProviderDetails providerDetails = clientRegistration.getProviderDetails();
		ClientRegistration.ProviderDetails.UserInfoEndpoint userInfoEndpoint = providerDetails.getUserInfoEndpoint();
		String scopes = "";
		if (!CollectionUtils.isEmpty(clientRegistration.getScopes())) {
			scopes = StringUtils.collectionToDelimitedString(clientRegistration.getScopes(), ",", "\"", "\"");
		}
		String configurationMetadata = "\"@class\": \"java.util.Collections$UnmodifiableMap\"";
		if (!CollectionUtils.isEmpty(providerDetails.getConfigurationMetadata())) {
			configurationMetadata += "," + providerDetails.getConfigurationMetadata()
				.keySet()
				.stream()
				.map((key) -> "\"" + key + "\": \"" + providerDetails.getConfigurationMetadata().get(key) + "\"")
				.collect(Collectors.joining(","));
		}
		// @formatter:off
		return "{\n" +
				"    \"@class\": \"org.springframework.security.oauth2.client.registration.ClientRegistration\",\n" +
				"    \"registrationId\": \"" + clientRegistration.getRegistrationId() + "\",\n" +
				"    \"clientId\": \"" + clientRegistration.getClientId() + "\",\n" +
				"    \"clientSecret\": \"" + clientRegistration.getClientSecret() + "\",\n" +
				"    \"clientAuthenticationMethod\": {\n" +
				"      \"value\": \"" + clientRegistration.getClientAuthenticationMethod().getValue() + "\"\n" +
				"    },\n" +
				"    \"authorizationGrantType\": {\n" +
				"      \"value\": \"" + clientRegistration.getAuthorizationGrantType().getValue() + "\"\n" +
				"    },\n" +
				"    \"redirectUri\": \"" + clientRegistration.getRedirectUri() + "\",\n" +
				"    \"scopes\": [\n" +
				"      \"java.util.Collections$UnmodifiableSet\",\n" +
				"      [" + scopes + "]\n" +
				"    ],\n" +
				"    \"providerDetails\": {\n" +
				"      \"@class\": \"org.springframework.security.oauth2.client.registration.ClientRegistration$ProviderDetails\",\n" +
				"      \"authorizationUri\": \"" + providerDetails.getAuthorizationUri() + "\",\n" +
				"      \"tokenUri\": \"" + providerDetails.getTokenUri() + "\",\n" +
				"      \"userInfoEndpoint\": {\n" +
				"        \"@class\": \"org.springframework.security.oauth2.client.registration.ClientRegistration$ProviderDetails$UserInfoEndpoint\",\n" +
				"        \"uri\": " + ((userInfoEndpoint.getUri() != null) ? "\"" + userInfoEndpoint.getUri() + "\"" : null) + ",\n" +
				"        \"authenticationMethod\": {\n" +
				"          \"value\": \"" + userInfoEndpoint.getAuthenticationMethod().getValue() + "\"\n" +
				"        },\n" +
				"        \"userNameAttributeName\": " + ((userInfoEndpoint.getUserNameAttributeName() != null) ? "\"" + userInfoEndpoint.getUserNameAttributeName() + "\"" : null) + "\n" +
				"      },\n" +
				"      \"jwkSetUri\": " + ((providerDetails.getJwkSetUri() != null) ? "\"" + providerDetails.getJwkSetUri() + "\"" : null) + ",\n" +
				"      \"issuerUri\": " + ((providerDetails.getIssuerUri() != null) ? "\"" + providerDetails.getIssuerUri() + "\"" : null) + ",\n" +
				"      \"configurationMetadata\": {\n" +
				"        " + configurationMetadata + "\n" +
				"      }\n" +
				"    },\n" +
				"    \"clientName\": \"" + clientRegistration.getClientName() + "\",\n" +
				"    \"clientSettings\": {\n" +
				"      \"requireProofKey\": " + clientRegistration.getClientSettings().isRequireProofKey() + "\n" +
				"    }\n" +
				"}";
		// @formatter:on
	}

	private static String asJson(OAuth2AccessToken accessToken) {
		String scopes = "";
		if (!CollectionUtils.isEmpty(accessToken.getScopes())) {
			scopes = StringUtils.collectionToDelimitedString(accessToken.getScopes(), ",", "\"", "\"");
		}
		// @formatter:off
		return "{\n" +
				"    \"@class\": \"org.springframework.security.oauth2.core.OAuth2AccessToken\",\n" +
				"    \"tokenType\": {\n" +
				"      \"value\": \"" + accessToken.getTokenType().getValue() + "\"\n" +
				"    },\n" +
				"    \"tokenValue\": \"" + accessToken.getTokenValue() + "\",\n" +
				"    \"issuedAt\": " + toString(accessToken.getIssuedAt()) + ",\n" +
				"    \"expiresAt\": " + toString(accessToken.getExpiresAt()) + ",\n" +
				"    \"scopes\": [\n" +
				"      \"java.util.Collections$UnmodifiableSet\",\n" +
				"      [" + scopes + "]\n" +
				"    ]\n" +
				"}";
		// @formatter:on
	}

	private static String asJson(OAuth2RefreshToken refreshToken) {
		if (refreshToken == null) {
			return null;
		}
		// @formatter:off
		return "{\n" +
				"    \"@class\": \"org.springframework.security.oauth2.core.OAuth2RefreshToken\",\n" +
				"    \"tokenValue\": \"" + refreshToken.getTokenValue() + "\",\n" +
				"    \"issuedAt\": " + toString(refreshToken.getIssuedAt()) + ",\n" +
				"    \"expiresAt\": " + toString(refreshToken.getExpiresAt()) + "\n" +
				"}";
		// @formatter:on
	}

	private static String toString(Instant instant) {
		if (instant == null) {
			return null;
		}
		return DecimalUtils.toBigDecimal(instant.getEpochSecond(), instant.getNano()).toString();
	}

}
