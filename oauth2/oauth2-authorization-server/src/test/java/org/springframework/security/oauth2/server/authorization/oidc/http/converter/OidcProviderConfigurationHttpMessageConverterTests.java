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
package org.springframework.security.oauth2.server.authorization.oidc.http.converter;

import java.net.URL;
import java.util.Arrays;
import java.util.Map;

import org.junit.jupiter.api.Test;

import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.mock.http.MockHttpOutputMessage;
import org.springframework.mock.http.client.MockClientHttpResponse;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.oidc.OidcProviderConfiguration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link OidcProviderConfigurationHttpMessageConverter}
 *
 * @author Daniel Garnier-Moiroux
 */
public class OidcProviderConfigurationHttpMessageConverterTests {

	private final OidcProviderConfigurationHttpMessageConverter messageConverter = new OidcProviderConfigurationHttpMessageConverter();

	@Test
	public void supportsWhenOidcProviderConfigurationThenTrue() {
		assertThat(this.messageConverter.supports(OidcProviderConfiguration.class)).isTrue();
	}

	@Test
	public void setProviderConfigurationParametersConverterWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> this.messageConverter.setProviderConfigurationParametersConverter(null));
	}

	@Test
	public void setProviderConfigurationConverterWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> this.messageConverter.setProviderConfigurationConverter(null));
	}

	@Test
	public void readInternalWhenRequiredParametersThenSuccess() throws Exception {
		// @formatter:off
		String providerConfigurationResponse = "{\n"
				+ "		\"issuer\": \"https://example.com\",\n"
				+ "		\"authorization_endpoint\": \"https://example.com/oauth2/authorize\",\n"
				+ "		\"token_endpoint\": \"https://example.com/oauth2/token\",\n"
				+ "		\"jwks_uri\": \"https://example.com/oauth2/jwks\",\n"
				+ "		\"response_types_supported\": [\"code\"],\n"
				+ "		\"subject_types_supported\": [\"public\"],\n"
				+ "		\"id_token_signing_alg_values_supported\": [\"RS256\"]\n"
				+ "}\n";
		// @formatter:on
		MockClientHttpResponse response = new MockClientHttpResponse(providerConfigurationResponse.getBytes(),
				HttpStatus.OK);
		OidcProviderConfiguration providerConfiguration = this.messageConverter
			.readInternal(OidcProviderConfiguration.class, response);

		assertThat(providerConfiguration.getIssuer()).isEqualTo(new URL("https://example.com"));
		assertThat(providerConfiguration.getAuthorizationEndpoint())
			.isEqualTo(new URL("https://example.com/oauth2/authorize"));
		assertThat(providerConfiguration.getTokenEndpoint()).isEqualTo(new URL("https://example.com/oauth2/token"));
		assertThat(providerConfiguration.getJwkSetUrl()).isEqualTo(new URL("https://example.com/oauth2/jwks"));
		assertThat(providerConfiguration.getResponseTypes()).containsExactly("code");
		assertThat(providerConfiguration.getSubjectTypes()).containsExactly("public");
		assertThat(providerConfiguration.getIdTokenSigningAlgorithms()).containsExactly("RS256");
		assertThat(providerConfiguration.getScopes()).isNull();
		assertThat(providerConfiguration.getGrantTypes()).isNull();
		assertThat(providerConfiguration.getTokenEndpointAuthenticationMethods()).isNull();
	}

	@Test
	public void readInternalWhenValidParametersThenSuccess() throws Exception {
		// @formatter:off
		String providerConfigurationResponse = "{\n"
				+ "		\"issuer\": \"https://example.com\",\n"
				+ "		\"authorization_endpoint\": \"https://example.com/oauth2/authorize\",\n"
				+ "		\"token_endpoint\": \"https://example.com/oauth2/token\",\n"
				+ "		\"jwks_uri\": \"https://example.com/oauth2/jwks\",\n"
				+ "		\"userinfo_endpoint\": \"https://example.com/userinfo\",\n"
				+ "		\"scopes_supported\": [\"openid\"],\n"
				+ "		\"response_types_supported\": [\"code\"],\n"
				+ "		\"grant_types_supported\": [\"authorization_code\", \"client_credentials\"],\n"
				+ "		\"subject_types_supported\": [\"public\"],\n"
				+ "		\"id_token_signing_alg_values_supported\": [\"RS256\"],\n"
				+ "		\"token_endpoint_auth_methods_supported\": [\"client_secret_basic\"],\n"
				+ "		\"custom_claim\": \"value\",\n"
				+ "		\"custom_collection_claim\": [\"value1\", \"value2\"]\n"
				+ "}\n";
		// @formatter:on
		MockClientHttpResponse response = new MockClientHttpResponse(providerConfigurationResponse.getBytes(),
				HttpStatus.OK);
		OidcProviderConfiguration providerConfiguration = this.messageConverter
			.readInternal(OidcProviderConfiguration.class, response);

		assertThat(providerConfiguration.getIssuer()).isEqualTo(new URL("https://example.com"));
		assertThat(providerConfiguration.getAuthorizationEndpoint())
			.isEqualTo(new URL("https://example.com/oauth2/authorize"));
		assertThat(providerConfiguration.getTokenEndpoint()).isEqualTo(new URL("https://example.com/oauth2/token"));
		assertThat(providerConfiguration.getJwkSetUrl()).isEqualTo(new URL("https://example.com/oauth2/jwks"));
		assertThat(providerConfiguration.getUserInfoEndpoint()).isEqualTo(new URL("https://example.com/userinfo"));
		assertThat(providerConfiguration.getScopes()).containsExactly("openid");
		assertThat(providerConfiguration.getResponseTypes()).containsExactly("code");
		assertThat(providerConfiguration.getGrantTypes()).containsExactlyInAnyOrder("authorization_code",
				"client_credentials");
		assertThat(providerConfiguration.getSubjectTypes()).containsExactly("public");
		assertThat(providerConfiguration.getIdTokenSigningAlgorithms()).containsExactly("RS256");
		assertThat(providerConfiguration.getTokenEndpointAuthenticationMethods())
			.containsExactly(ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue());
		assertThat(providerConfiguration.<String>getClaim("custom_claim")).isEqualTo("value");
		assertThat(providerConfiguration.getClaimAsStringList("custom_collection_claim"))
			.containsExactlyInAnyOrder("value1", "value2");
	}

	@Test
	public void readInternalWhenFailingConverterThenThrowException() {
		String errorMessage = "this is not a valid converter";
		this.messageConverter.setProviderConfigurationConverter((source) -> {
			throw new RuntimeException(errorMessage);
		});
		MockClientHttpResponse response = new MockClientHttpResponse("{}".getBytes(), HttpStatus.OK);

		assertThatExceptionOfType(HttpMessageNotReadableException.class)
			.isThrownBy(() -> this.messageConverter.readInternal(OidcProviderConfiguration.class, response))
			.withMessageContaining("An error occurred reading the OpenID Provider Configuration")
			.withMessageContaining(errorMessage);
	}

	@Test
	public void readInternalWhenInvalidProviderConfigurationThenThrowException() {
		String providerConfigurationResponse = "{ \"issuer\": null }";
		MockClientHttpResponse response = new MockClientHttpResponse(providerConfigurationResponse.getBytes(),
				HttpStatus.OK);

		assertThatExceptionOfType(HttpMessageNotReadableException.class)
			.isThrownBy(() -> this.messageConverter.readInternal(OidcProviderConfiguration.class, response))
			.withMessageContaining("An error occurred reading the OpenID Provider Configuration")
			.withMessageContaining("issuer cannot be null");
	}

	@Test
	public void writeInternalWhenProviderConfigurationThenSuccess() {
		OidcProviderConfiguration providerConfiguration = OidcProviderConfiguration.builder()
			.issuer("https://example.com")
			.authorizationEndpoint("https://example.com/oauth2/authorize")
			.tokenEndpoint("https://example.com/oauth2/token")
			.jwkSetUrl("https://example.com/oauth2/jwks")
			.userInfoEndpoint("https://example.com/userinfo")
			.scope("openid")
			.responseType("code")
			.grantType("authorization_code")
			.grantType("client_credentials")
			.subjectType("public")
			.idTokenSigningAlgorithm("RS256")
			.tokenEndpointAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue())
			.claim("custom_claim", "value")
			.claim("custom_collection_claim", Arrays.asList("value1", "value2"))
			.build();
		MockHttpOutputMessage outputMessage = new MockHttpOutputMessage();

		this.messageConverter.writeInternal(providerConfiguration, outputMessage);

		String providerConfigurationResponse = outputMessage.getBodyAsString();
		assertThat(providerConfigurationResponse).contains("\"issuer\":\"https://example.com\"");
		assertThat(providerConfigurationResponse)
			.contains("\"authorization_endpoint\":\"https://example.com/oauth2/authorize\"");
		assertThat(providerConfigurationResponse).contains("\"token_endpoint\":\"https://example.com/oauth2/token\"");
		assertThat(providerConfigurationResponse).contains("\"jwks_uri\":\"https://example.com/oauth2/jwks\"");
		assertThat(providerConfigurationResponse).contains("\"userinfo_endpoint\":\"https://example.com/userinfo\"");
		assertThat(providerConfigurationResponse).contains("\"scopes_supported\":[\"openid\"]");
		assertThat(providerConfigurationResponse).contains("\"response_types_supported\":[\"code\"]");
		assertThat(providerConfigurationResponse)
			.contains("\"grant_types_supported\":[\"authorization_code\",\"client_credentials\"]");
		assertThat(providerConfigurationResponse).contains("\"subject_types_supported\":[\"public\"]");
		assertThat(providerConfigurationResponse).contains("\"id_token_signing_alg_values_supported\":[\"RS256\"]");
		assertThat(providerConfigurationResponse)
			.contains("\"token_endpoint_auth_methods_supported\":[\"client_secret_basic\"]");
		assertThat(providerConfigurationResponse).contains("\"custom_claim\":\"value\"");
		assertThat(providerConfigurationResponse).contains("\"custom_collection_claim\":[\"value1\",\"value2\"]");
	}

	@Test
	public void writeInternalWhenWriteFailsThenThrowsException() {
		String errorMessage = "this is not a valid converter";
		Converter<OidcProviderConfiguration, Map<String, Object>> failingConverter = (source) -> {
			throw new RuntimeException(errorMessage);
		};
		this.messageConverter.setProviderConfigurationParametersConverter(failingConverter);

		OidcProviderConfiguration providerConfiguration = OidcProviderConfiguration.builder()
			.issuer("https://example.com")
			.authorizationEndpoint("https://example.com/oauth2/authorize")
			.tokenEndpoint("https://example.com/oauth2/token")
			.jwkSetUrl("https://example.com/oauth2/jwks")
			.responseType("code")
			.subjectType("public")
			.idTokenSigningAlgorithm("RS256")
			.build();

		MockHttpOutputMessage outputMessage = new MockHttpOutputMessage();

		assertThatExceptionOfType(HttpMessageNotWritableException.class)
			.isThrownBy(() -> this.messageConverter.writeInternal(providerConfiguration, outputMessage))
			.withMessageContaining("An error occurred writing the OpenID Provider Configuration")
			.withMessageContaining(errorMessage);
	}

}
