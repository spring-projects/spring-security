/*
 * Copyright 2020-2022 the original author or authors.
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
import java.util.Arrays;
import java.util.Map;

import org.junit.jupiter.api.Test;

import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.mock.http.MockHttpOutputMessage;
import org.springframework.mock.http.client.MockClientHttpResponse;
import org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenIntrospection;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link OAuth2TokenIntrospectionHttpMessageConverter}
 *
 * @author Gerardo Roza
 * @author Joe Grandja
 */
public class OAuth2TokenIntrospectionHttpMessageConverterTests {

	private final OAuth2TokenIntrospectionHttpMessageConverter messageConverter = new OAuth2TokenIntrospectionHttpMessageConverter();

	@Test
	public void supportsWhenOAuth2TokenIntrospectionThenTrue() {
		assertThat(this.messageConverter.supports(OAuth2TokenIntrospection.class)).isTrue();
	}

	@Test
	public void setTokenIntrospectionParametersConverterWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> this.messageConverter.setTokenIntrospectionParametersConverter(null));
	}

	@Test
	public void setTokenIntrospectionConverterWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> this.messageConverter.setTokenIntrospectionConverter(null));
	}

	@Test
	public void readInternalWhenValidParametersThenSuccess() throws Exception {
		// @formatter:off
		String tokenIntrospectionResponseBody = "{\n"
				+ "		\"active\": true,\n"
				+ "		\"client_id\": \"clientId1\",\n"
				+ "		\"username\": \"username1\",\n"
				+ "		\"iat\": 1607633867,\n"
				+ "		\"exp\": 1607637467,\n"
				+ "		\"scope\": \"scope1 scope2\",\n"
				+ "		\"token_type\": \"Bearer\",\n"
				+ "		\"nbf\": 1607633867,\n"
				+ "		\"sub\": \"subject1\",\n"
				+ "		\"aud\": [\"audience1\", \"audience2\"],\n"
				+ "		\"iss\": \"https://example.com/issuer1\",\n"
				+ "		\"jti\": \"jwtId1\"\n"
				+ "}\n";
		// @formatter:on
		MockClientHttpResponse response = new MockClientHttpResponse(tokenIntrospectionResponseBody.getBytes(),
				HttpStatus.OK);
		OAuth2TokenIntrospection tokenIntrospectionResponse = this.messageConverter
			.readInternal(OAuth2TokenIntrospection.class, response);

		assertThat(tokenIntrospectionResponse.isActive()).isTrue();
		assertThat(tokenIntrospectionResponse.getClientId()).isEqualTo("clientId1");
		assertThat(tokenIntrospectionResponse.getUsername()).isEqualTo("username1");
		assertThat(tokenIntrospectionResponse.getIssuedAt()).isEqualTo(Instant.ofEpochSecond(1607633867L));
		assertThat(tokenIntrospectionResponse.getExpiresAt()).isEqualTo(Instant.ofEpochSecond(1607637467L));
		assertThat(tokenIntrospectionResponse.getScopes())
			.containsExactlyInAnyOrderElementsOf(Arrays.asList("scope1", "scope2"));
		assertThat(tokenIntrospectionResponse.getTokenType()).isEqualTo("Bearer");
		assertThat(tokenIntrospectionResponse.getNotBefore()).isEqualTo(Instant.ofEpochSecond(1607633867L));
		assertThat(tokenIntrospectionResponse.getSubject()).isEqualTo("subject1");
		assertThat(tokenIntrospectionResponse.getAudience())
			.containsExactlyInAnyOrderElementsOf(Arrays.asList("audience1", "audience2"));
		assertThat(tokenIntrospectionResponse.getIssuer()).isEqualTo(new URL("https://example.com/issuer1"));
		assertThat(tokenIntrospectionResponse.getId()).isEqualTo("jwtId1");
	}

	@Test
	public void readInternalWhenFailingConverterThenThrowException() {
		String errorMessage = "this is not a valid converter";
		this.messageConverter.setTokenIntrospectionConverter((source) -> {
			throw new RuntimeException(errorMessage);
		});
		MockClientHttpResponse response = new MockClientHttpResponse("{}".getBytes(), HttpStatus.OK);

		assertThatExceptionOfType(HttpMessageNotReadableException.class)
			.isThrownBy(() -> this.messageConverter.readInternal(OAuth2TokenIntrospection.class, response))
			.withMessageContaining("An error occurred reading the Token Introspection Response")
			.withMessageContaining(errorMessage);
	}

	@Test
	public void writeInternalWhenTokenIntrospectionThenSuccess() {
		// @formatter:off
		OAuth2TokenIntrospection tokenClaims = OAuth2TokenIntrospection.builder(true)
				.clientId("clientId1")
				.username("username1")
				.issuedAt(Instant.ofEpochSecond(1607633867))
				.expiresAt(Instant.ofEpochSecond(1607637467))
				.scope("scope1 scope2")
				.tokenType(TokenType.BEARER.getValue())
				.notBefore(Instant.ofEpochSecond(1607633867))
				.subject("subject1")
				.audience("audience1")
				.audience("audience2")
				.issuer("https://example.com/issuer1")
				.id("jwtId1")
				.build();
		// @formatter:on
		MockHttpOutputMessage outputMessage = new MockHttpOutputMessage();

		this.messageConverter.writeInternal(tokenClaims, outputMessage);

		String tokenIntrospectionResponse = outputMessage.getBodyAsString();
		assertThat(tokenIntrospectionResponse).contains("\"active\":true");
		assertThat(tokenIntrospectionResponse).contains("\"client_id\":\"clientId1\"");
		assertThat(tokenIntrospectionResponse).contains("\"username\":\"username1\"");
		assertThat(tokenIntrospectionResponse).contains("\"iat\":1607633867");
		assertThat(tokenIntrospectionResponse).contains("\"exp\":1607637467");
		assertThat(tokenIntrospectionResponse).contains("\"scope\":\"scope1 scope2\"");
		assertThat(tokenIntrospectionResponse).contains("\"token_type\":\"Bearer\"");
		assertThat(tokenIntrospectionResponse).contains("\"nbf\":1607633867");
		assertThat(tokenIntrospectionResponse).contains("\"sub\":\"subject1\"");
		assertThat(tokenIntrospectionResponse).contains("\"aud\":[\"audience1\",\"audience2\"]");
		assertThat(tokenIntrospectionResponse).contains("\"iss\":\"https://example.com/issuer1\"");
		assertThat(tokenIntrospectionResponse).contains("\"jti\":\"jwtId1\"");
	}

	@Test
	public void writeInternalWhenWriteFailsThenThrowsException() {
		String errorMessage = "this is not a valid converter";
		Converter<OAuth2TokenIntrospection, Map<String, Object>> failingConverter = (source) -> {
			throw new RuntimeException(errorMessage);
		};
		this.messageConverter.setTokenIntrospectionParametersConverter(failingConverter);

		OAuth2TokenIntrospection tokenClaims = OAuth2TokenIntrospection.builder().build();

		MockHttpOutputMessage outputMessage = new MockHttpOutputMessage();

		assertThatThrownBy(() -> this.messageConverter.writeInternal(tokenClaims, outputMessage))
			.isInstanceOf(HttpMessageNotWritableException.class)
			.hasMessageContaining("An error occurred writing the Token Introspection Response")
			.hasMessageContaining(errorMessage);
	}

}
