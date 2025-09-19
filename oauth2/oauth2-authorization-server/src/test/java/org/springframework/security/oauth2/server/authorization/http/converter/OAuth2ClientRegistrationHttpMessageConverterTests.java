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

package org.springframework.security.oauth2.server.authorization.http.converter;

import java.net.URL;
import java.time.Instant;
import java.util.Map;

import org.junit.jupiter.api.Test;

import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.mock.http.MockHttpOutputMessage;
import org.springframework.mock.http.client.MockClientHttpResponse;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.server.authorization.OAuth2ClientRegistration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link OAuth2ClientRegistrationHttpMessageConverter}
 *
 * @author Joe Grandja
 * @since 7.0
 */
public class OAuth2ClientRegistrationHttpMessageConverterTests {

	private final OAuth2ClientRegistrationHttpMessageConverter messageConverter = new OAuth2ClientRegistrationHttpMessageConverter();

	@Test
	public void supportsWhenOAuth2ClientRegistrationThenTrue() {
		assertThat(this.messageConverter.supports(OAuth2ClientRegistration.class)).isTrue();
	}

	@Test
	public void setClientRegistrationConverterWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> this.messageConverter.setClientRegistrationConverter(null))
			.withMessageContaining("clientRegistrationConverter cannot be null");
	}

	@Test
	public void setClientRegistrationParametersConverterWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> this.messageConverter.setClientRegistrationParametersConverter(null))
			.withMessageContaining("clientRegistrationParametersConverter cannot be null");
	}

	@Test
	public void readInternalWhenValidParametersThenSuccess() throws Exception {
		// @formatter:off
		String clientRegistrationRequest = "{\n"
				+ "		\"client_id\": \"client-id\",\n"
				+ "		\"client_id_issued_at\": 1607633867,\n"
				+ "		\"client_secret\": \"client-secret\",\n"
				+ "		\"client_secret_expires_at\": 1607637467,\n"
				+ "		\"client_name\": \"client-name\",\n"
				+ "		\"redirect_uris\": [\n"
				+ "			\"https://client.example.com\"\n"
				+ "		],\n"
				+ "		\"token_endpoint_auth_method\": \"client_secret_basic\",\n"
				+ "		\"grant_types\": [\n"
				+ "			\"authorization_code\",\n"
				+ "			\"client_credentials\"\n"
				+ "		],\n"
				+ "		\"response_types\":[\n"
				+ "			\"code\"\n"
				+ "		],\n"
				+ "		\"scope\": \"scope1 scope2\",\n"
				+ "		\"jwks_uri\": \"https://client.example.com/jwks\",\n"
				+ "		\"a-claim\": \"a-value\"\n"
				+ "}\n";
		// @formatter:on
		MockClientHttpResponse response = new MockClientHttpResponse(clientRegistrationRequest.getBytes(),
				HttpStatus.OK);
		OAuth2ClientRegistration clientRegistration = this.messageConverter.readInternal(OAuth2ClientRegistration.class,
				response);

		assertThat(clientRegistration.getClientId()).isEqualTo("client-id");
		assertThat(clientRegistration.getClientIdIssuedAt()).isEqualTo(Instant.ofEpochSecond(1607633867L));
		assertThat(clientRegistration.getClientSecret()).isEqualTo("client-secret");
		assertThat(clientRegistration.getClientSecretExpiresAt()).isEqualTo(Instant.ofEpochSecond(1607637467L));
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
	public void readInternalWhenClientSecretNoExpiryThenSuccess() {
		// @formatter:off
		String clientRegistrationRequest = "{\n"
				+ "		\"client_id\": \"client-id\",\n"
				+ "		\"client_secret\": \"client-secret\",\n"
				+ "		\"client_secret_expires_at\": 0,\n"
				+ "		\"redirect_uris\": [\n"
				+ "			\"https://client.example.com\"\n"
				+ "		]\n"
				+ "}\n";
		// @formatter:on
		MockClientHttpResponse response = new MockClientHttpResponse(clientRegistrationRequest.getBytes(),
				HttpStatus.OK);
		OAuth2ClientRegistration clientRegistration = this.messageConverter.readInternal(OAuth2ClientRegistration.class,
				response);

		assertThat(clientRegistration.getClaims()).hasSize(3);
		assertThat(clientRegistration.getClientId()).isEqualTo("client-id");
		assertThat(clientRegistration.getClientSecret()).isEqualTo("client-secret");
		assertThat(clientRegistration.getClientSecretExpiresAt()).isNull();
		assertThat(clientRegistration.getRedirectUris()).containsOnly("https://client.example.com");
	}

	@Test
	public void readInternalWhenFailingConverterThenThrowException() {
		String errorMessage = "this is not a valid converter";
		this.messageConverter.setClientRegistrationConverter((source) -> {
			throw new RuntimeException(errorMessage);
		});
		MockClientHttpResponse response = new MockClientHttpResponse("{}".getBytes(), HttpStatus.OK);

		assertThatExceptionOfType(HttpMessageNotReadableException.class)
			.isThrownBy(() -> this.messageConverter.readInternal(OAuth2ClientRegistration.class, response))
			.withMessageContaining("An error occurred reading the OAuth 2.0 Client Registration")
			.withMessageContaining(errorMessage);
	}

	@Test
	public void writeInternalWhenClientRegistrationThenSuccess() {
		// @formatter:off
		OAuth2ClientRegistration clientRegistration = OAuth2ClientRegistration.builder()
				.clientId("client-id")
				.clientIdIssuedAt(Instant.ofEpochSecond(1607633867))
				.clientSecret("client-secret")
				.clientSecretExpiresAt(Instant.ofEpochSecond(1607637467))
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

		MockHttpOutputMessage outputMessage = new MockHttpOutputMessage();
		this.messageConverter.writeInternal(clientRegistration, outputMessage);

		String clientRegistrationResponse = outputMessage.getBodyAsString();
		assertThat(clientRegistrationResponse).contains("\"client_id\":\"client-id\"");
		assertThat(clientRegistrationResponse).contains("\"client_id_issued_at\":1607633867");
		assertThat(clientRegistrationResponse).contains("\"client_secret\":\"client-secret\"");
		assertThat(clientRegistrationResponse).contains("\"client_secret_expires_at\":1607637467");
		assertThat(clientRegistrationResponse).contains("\"client_name\":\"client-name\"");
		assertThat(clientRegistrationResponse).contains("\"redirect_uris\":[\"https://client.example.com\"]");
		assertThat(clientRegistrationResponse).contains("\"token_endpoint_auth_method\":\"client_secret_basic\"");
		assertThat(clientRegistrationResponse)
			.contains("\"grant_types\":[\"authorization_code\",\"client_credentials\"]");
		assertThat(clientRegistrationResponse).contains("\"response_types\":[\"code\"]");
		assertThat(clientRegistrationResponse).contains("\"scope\":\"scope1 scope2\"");
		assertThat(clientRegistrationResponse).contains("\"jwks_uri\":\"https://client.example.com/jwks\"");
		assertThat(clientRegistrationResponse).contains("\"a-claim\":\"a-value\"");
	}

	@Test
	public void writeInternalWhenClientSecretNoExpiryThenSuccess() {
		// @formatter:off
		OAuth2ClientRegistration clientRegistration = OAuth2ClientRegistration.builder()
				.clientId("client-id")
				.clientSecret("client-secret")
				.redirectUri("https://client.example.com")
				.build();
		// @formatter:on

		MockHttpOutputMessage outputMessage = new MockHttpOutputMessage();
		this.messageConverter.writeInternal(clientRegistration, outputMessage);

		String clientRegistrationResponse = outputMessage.getBodyAsString();
		assertThat(clientRegistrationResponse).contains("\"client_id\":\"client-id\"");
		assertThat(clientRegistrationResponse).contains("\"client_secret\":\"client-secret\"");
		assertThat(clientRegistrationResponse).contains("\"client_secret_expires_at\":0");
		assertThat(clientRegistrationResponse).contains("\"redirect_uris\":[\"https://client.example.com\"]");
	}

	@Test
	public void writeInternalWhenWriteFailsThenThrowException() {
		String errorMessage = "this is not a valid converter";
		Converter<OAuth2ClientRegistration, Map<String, Object>> failingConverter = (source) -> {
			throw new RuntimeException(errorMessage);
		};
		this.messageConverter.setClientRegistrationParametersConverter(failingConverter);

		// @formatter:off
		OAuth2ClientRegistration clientRegistration = OAuth2ClientRegistration.builder()
				.redirectUri("https://client.example.com")
				.build();
		// @formatter:off

		MockHttpOutputMessage outputMessage = new MockHttpOutputMessage();

		assertThatExceptionOfType(HttpMessageNotWritableException.class).isThrownBy(() -> this.messageConverter.writeInternal(clientRegistration, outputMessage))
				.withMessageContaining("An error occurred writing the OAuth 2.0 Client Registration")
				.withMessageContaining(errorMessage);
	}

}
