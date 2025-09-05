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
package org.springframework.security.oauth2.server.authorization.http.converter;

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
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationServerMetadata;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link OAuth2AuthorizationServerMetadataHttpMessageConverter}
 *
 * @author Daniel Garnier-Moiroux
 */
public class OAuth2AuthorizationServerMetadataHttpMessageConverterTests {

	private final OAuth2AuthorizationServerMetadataHttpMessageConverter messageConverter = new OAuth2AuthorizationServerMetadataHttpMessageConverter();

	@Test
	public void supportsWhenOAuth2AuthorizationServerMetadataThenTrue() {
		assertThat(this.messageConverter.supports(OAuth2AuthorizationServerMetadata.class)).isTrue();
	}

	@Test
	public void setAuthorizationServerMetadataParametersConverterWhenConverterIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> this.messageConverter.setAuthorizationServerMetadataParametersConverter(null));
	}

	@Test
	public void setAuthorizationServerMetadataConverterWhenConverterIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> this.messageConverter.setAuthorizationServerMetadataConverter(null));
	}

	@Test
	public void readInternalWhenRequiredParametersThenSuccess() throws Exception {
		// @formatter:off
		String authorizationServerMetadataResponse = "{\n"
				+ "		\"issuer\": \"https://example.com\",\n"
				+ "		\"authorization_endpoint\": \"https://example.com/oauth2/authorize\",\n"
				+ "		\"token_endpoint\": \"https://example.com/oauth2/token\",\n"
				+ "		\"response_types_supported\": [\"code\"]\n"
				+ "}\n";
		// @formatter:on
		MockClientHttpResponse response = new MockClientHttpResponse(authorizationServerMetadataResponse.getBytes(),
				HttpStatus.OK);
		OAuth2AuthorizationServerMetadata authorizationServerMetadata = this.messageConverter
			.readInternal(OAuth2AuthorizationServerMetadata.class, response);

		assertThat(authorizationServerMetadata.getIssuer()).isEqualTo(new URL("https://example.com"));
		assertThat(authorizationServerMetadata.getAuthorizationEndpoint())
			.isEqualTo(new URL("https://example.com/oauth2/authorize"));
		assertThat(authorizationServerMetadata.getTokenEndpoint())
			.isEqualTo(new URL("https://example.com/oauth2/token"));
		assertThat(authorizationServerMetadata.getTokenEndpointAuthenticationMethods()).isNull();
		assertThat(authorizationServerMetadata.getJwkSetUrl()).isNull();
		assertThat(authorizationServerMetadata.getResponseTypes()).containsExactly("code");
		assertThat(authorizationServerMetadata.getScopes()).isNull();
		assertThat(authorizationServerMetadata.getGrantTypes()).isNull();
		assertThat(authorizationServerMetadata.getTokenRevocationEndpoint()).isNull();
		assertThat(authorizationServerMetadata.getTokenRevocationEndpointAuthenticationMethods()).isNull();
		assertThat(authorizationServerMetadata.getTokenIntrospectionEndpoint()).isNull();
		assertThat(authorizationServerMetadata.getTokenIntrospectionEndpointAuthenticationMethods()).isNull();
		assertThat(authorizationServerMetadata.getCodeChallengeMethods()).isNull();
	}

	@Test
	public void readInternalWhenValidParametersThenSuccess() throws Exception {
		// @formatter:off
		String authorizationServerMetadataResponse = "{\n"
				+ "		\"issuer\": \"https://example.com\",\n"
				+ "		\"authorization_endpoint\": \"https://example.com/oauth2/authorize\",\n"
				+ "		\"token_endpoint\": \"https://example.com/oauth2/token\",\n"
				+ "		\"token_endpoint_auth_methods_supported\": [\"client_secret_basic\"],\n"
				+ "		\"jwks_uri\": \"https://example.com/oauth2/jwks\",\n"
				+ "		\"scopes_supported\": [\"openid\"],\n"
				+ "		\"response_types_supported\": [\"code\"],\n"
				+ "		\"grant_types_supported\": [\"authorization_code\", \"client_credentials\"],\n"
				+ "		\"revocation_endpoint\": \"https://example.com/oauth2/revoke\",\n"
				+ "		\"revocation_endpoint_auth_methods_supported\": [\"client_secret_basic\"],\n"
				+ "		\"introspection_endpoint\": \"https://example.com/oauth2/introspect\",\n"
				+ "		\"introspection_endpoint_auth_methods_supported\": [\"client_secret_basic\"],\n"
				+ "		\"code_challenge_methods_supported\": [\"S256\"],\n"
				+ "		\"custom_claim\": \"value\",\n"
				+ "		\"custom_collection_claim\": [\"value1\", \"value2\"]\n"
				+ "}\n";
		// @formatter:on
		MockClientHttpResponse response = new MockClientHttpResponse(authorizationServerMetadataResponse.getBytes(),
				HttpStatus.OK);
		OAuth2AuthorizationServerMetadata authorizationServerMetadata = this.messageConverter
			.readInternal(OAuth2AuthorizationServerMetadata.class, response);

		assertThat(authorizationServerMetadata.getClaims()).hasSize(15);
		assertThat(authorizationServerMetadata.getIssuer()).isEqualTo(new URL("https://example.com"));
		assertThat(authorizationServerMetadata.getAuthorizationEndpoint())
			.isEqualTo(new URL("https://example.com/oauth2/authorize"));
		assertThat(authorizationServerMetadata.getTokenEndpoint())
			.isEqualTo(new URL("https://example.com/oauth2/token"));
		assertThat(authorizationServerMetadata.getTokenEndpointAuthenticationMethods())
			.containsExactly(ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue());
		assertThat(authorizationServerMetadata.getJwkSetUrl()).isEqualTo(new URL("https://example.com/oauth2/jwks"));
		assertThat(authorizationServerMetadata.getScopes()).containsExactly("openid");
		assertThat(authorizationServerMetadata.getResponseTypes()).containsExactly("code");
		assertThat(authorizationServerMetadata.getGrantTypes()).containsExactlyInAnyOrder("authorization_code",
				"client_credentials");
		assertThat(authorizationServerMetadata.getTokenRevocationEndpoint())
			.isEqualTo(new URL("https://example.com/oauth2/revoke"));
		assertThat(authorizationServerMetadata.getTokenRevocationEndpointAuthenticationMethods())
			.containsExactly(ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue());
		assertThat(authorizationServerMetadata.getTokenIntrospectionEndpoint())
			.isEqualTo(new URL("https://example.com/oauth2/introspect"));
		assertThat(authorizationServerMetadata.getTokenIntrospectionEndpointAuthenticationMethods())
			.containsExactly(ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue());
		assertThat(authorizationServerMetadata.getCodeChallengeMethods()).containsExactly("S256");
		assertThat(authorizationServerMetadata.getClaimAsString("custom_claim")).isEqualTo("value");
		assertThat(authorizationServerMetadata.getClaimAsStringList("custom_collection_claim"))
			.containsExactlyInAnyOrder("value1", "value2");
	}

	@Test
	public void readInternalWhenFailingConverterThenThrowException() {
		String errorMessage = "this is not a valid converter";
		this.messageConverter.setAuthorizationServerMetadataConverter((source) -> {
			throw new RuntimeException(errorMessage);
		});
		MockClientHttpResponse response = new MockClientHttpResponse("{}".getBytes(), HttpStatus.OK);

		assertThatExceptionOfType(HttpMessageNotReadableException.class)
			.isThrownBy(() -> this.messageConverter.readInternal(OAuth2AuthorizationServerMetadata.class, response))
			.withMessageContaining("An error occurred reading the OAuth 2.0 Authorization Server Metadata")
			.withMessageContaining(errorMessage);
	}

	@Test
	public void readInternalWhenInvalidOAuth2AuthorizationServerMetadataThenThrowException() {
		String authorizationServerMetadataResponse = "{ \"issuer\": null }";
		MockClientHttpResponse response = new MockClientHttpResponse(authorizationServerMetadataResponse.getBytes(),
				HttpStatus.OK);

		assertThatExceptionOfType(HttpMessageNotReadableException.class)
			.isThrownBy(() -> this.messageConverter.readInternal(OAuth2AuthorizationServerMetadata.class, response))
			.withMessageContaining("An error occurred reading the OAuth 2.0 Authorization Server Metadata")
			.withMessageContaining("issuer cannot be null");
	}

	@Test
	public void writeInternalWhenOAuth2AuthorizationServerMetadataThenSuccess() {
		OAuth2AuthorizationServerMetadata authorizationServerMetadata = OAuth2AuthorizationServerMetadata.builder()
			.issuer("https://example.com")
			.authorizationEndpoint("https://example.com/oauth2/authorize")
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
			.claim("custom_claim", "value")
			.claim("custom_collection_claim", Arrays.asList("value1", "value2"))
			.build();
		MockHttpOutputMessage outputMessage = new MockHttpOutputMessage();

		this.messageConverter.writeInternal(authorizationServerMetadata, outputMessage);

		String authorizationServerMetadataResponse = outputMessage.getBodyAsString();
		assertThat(authorizationServerMetadataResponse).contains("\"issuer\":\"https://example.com\"");
		assertThat(authorizationServerMetadataResponse)
			.contains("\"authorization_endpoint\":\"https://example.com/oauth2/authorize\"");
		assertThat(authorizationServerMetadataResponse)
			.contains("\"token_endpoint\":\"https://example.com/oauth2/token\"");
		assertThat(authorizationServerMetadataResponse)
			.contains("\"token_endpoint_auth_methods_supported\":[\"client_secret_basic\"]");
		assertThat(authorizationServerMetadataResponse).contains("\"jwks_uri\":\"https://example.com/oauth2/jwks\"");
		assertThat(authorizationServerMetadataResponse).contains("\"scopes_supported\":[\"openid\"]");
		assertThat(authorizationServerMetadataResponse).contains("\"response_types_supported\":[\"code\"]");
		assertThat(authorizationServerMetadataResponse)
			.contains("\"grant_types_supported\":[\"authorization_code\",\"client_credentials\"]");
		assertThat(authorizationServerMetadataResponse)
			.contains("\"revocation_endpoint\":\"https://example.com/oauth2/revoke\"");
		assertThat(authorizationServerMetadataResponse)
			.contains("\"revocation_endpoint_auth_methods_supported\":[\"client_secret_basic\"]");
		assertThat(authorizationServerMetadataResponse)
			.contains("\"introspection_endpoint\":\"https://example.com/oauth2/introspect\"");
		assertThat(authorizationServerMetadataResponse)
			.contains("\"introspection_endpoint_auth_methods_supported\":[\"client_secret_basic\"]");
		assertThat(authorizationServerMetadataResponse).contains("\"code_challenge_methods_supported\":[\"S256\"]");
		assertThat(authorizationServerMetadataResponse).contains("\"custom_claim\":\"value\"");
		assertThat(authorizationServerMetadataResponse).contains("\"custom_collection_claim\":[\"value1\",\"value2\"]");
	}

	@Test
	public void writeInternalWhenWriteFailsThenThrowException() {
		String errorMessage = "this is not a valid converter";
		Converter<OAuth2AuthorizationServerMetadata, Map<String, Object>> failingConverter = (source) -> {
			throw new RuntimeException(errorMessage);
		};
		this.messageConverter.setAuthorizationServerMetadataParametersConverter(failingConverter);

		MockHttpOutputMessage outputMessage = new MockHttpOutputMessage();
		OAuth2AuthorizationServerMetadata authorizationServerMetadata = OAuth2AuthorizationServerMetadata.builder()
			.issuer("https://example.com")
			.authorizationEndpoint("https://example.com/oauth2/authorize")
			.tokenEndpoint("https://example.com/oauth2/token")
			.responseType("code")
			.build();

		assertThatExceptionOfType(HttpMessageNotWritableException.class)
			.isThrownBy(() -> this.messageConverter.writeInternal(authorizationServerMetadata, outputMessage))
			.withMessageContaining("An error occurred writing the OAuth 2.0 Authorization Server Metadata")
			.withMessageContaining(errorMessage);
	}

}
