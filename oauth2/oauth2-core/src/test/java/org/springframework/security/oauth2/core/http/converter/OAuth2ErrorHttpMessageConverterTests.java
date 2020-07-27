/*
 * Copyright 2002-2020 the original author or authors.
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
package org.springframework.security.oauth2.core.http.converter;

import org.junit.Before;
import org.junit.Test;

import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.mock.http.MockHttpOutputMessage;
import org.springframework.mock.http.client.MockClientHttpResponse;
import org.springframework.security.oauth2.core.OAuth2Error;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link OAuth2ErrorHttpMessageConverter}.
 *
 * @author Joe Grandja
 */
public class OAuth2ErrorHttpMessageConverterTests {

	private OAuth2ErrorHttpMessageConverter messageConverter;

	@Before
	public void setup() {
		this.messageConverter = new OAuth2ErrorHttpMessageConverter();
	}

	@Test
	public void supportsWhenOAuth2ErrorThenTrue() {
		assertThat(this.messageConverter.supports(OAuth2Error.class)).isTrue();
	}

	@Test
	public void setErrorConverterWhenConverterIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.messageConverter.setErrorConverter(null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void setErrorParametersConverterWhenConverterIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.messageConverter.setErrorParametersConverter(null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void readInternalWhenErrorResponseThenReadOAuth2Error() throws Exception {
		String errorResponse = "{\n" + "	\"error\": \"unauthorized_client\",\n"
				+ "   \"error_description\": \"The client is not authorized\",\n"
				+ "   \"error_uri\": \"https://tools.ietf.org/html/rfc6749#section-5.2\"\n" + "}\n";

		MockClientHttpResponse response = new MockClientHttpResponse(errorResponse.getBytes(), HttpStatus.BAD_REQUEST);

		OAuth2Error oauth2Error = this.messageConverter.readInternal(OAuth2Error.class, response);
		assertThat(oauth2Error.getErrorCode()).isEqualTo("unauthorized_client");
		assertThat(oauth2Error.getDescription()).isEqualTo("The client is not authorized");
		assertThat(oauth2Error.getUri()).isEqualTo("https://tools.ietf.org/html/rfc6749#section-5.2");
	}

	// gh-8157
	@Test
	public void readInternalWhenErrorResponseWithObjectThenReadOAuth2Error() throws Exception {
		String errorResponse = "{\n" + "	\"error\": \"unauthorized_client\",\n"
				+ "   \"error_description\": \"The client is not authorized\",\n" + "   \"error_codes\": [65001],\n"
				+ "   \"error_uri\": \"https://tools.ietf.org/html/rfc6749#section-5.2\"\n" + "}\n";

		MockClientHttpResponse response = new MockClientHttpResponse(errorResponse.getBytes(), HttpStatus.BAD_REQUEST);

		OAuth2Error oauth2Error = this.messageConverter.readInternal(OAuth2Error.class, response);
		assertThat(oauth2Error.getErrorCode()).isEqualTo("unauthorized_client");
		assertThat(oauth2Error.getDescription()).isEqualTo("The client is not authorized");
		assertThat(oauth2Error.getUri()).isEqualTo("https://tools.ietf.org/html/rfc6749#section-5.2");
	}

	@Test
	public void readInternalWhenConversionFailsThenThrowHttpMessageNotReadableException() {
		Converter errorConverter = mock(Converter.class);
		given(errorConverter.convert(any())).willThrow(RuntimeException.class);
		this.messageConverter.setErrorConverter(errorConverter);

		String errorResponse = "{}";

		MockClientHttpResponse response = new MockClientHttpResponse(errorResponse.getBytes(), HttpStatus.BAD_REQUEST);

		assertThatThrownBy(() -> this.messageConverter.readInternal(OAuth2Error.class, response))
				.isInstanceOf(HttpMessageNotReadableException.class)
				.hasMessageContaining("An error occurred reading the OAuth 2.0 Error");
	}

	@Test
	public void writeInternalWhenOAuth2ErrorThenWriteErrorResponse() throws Exception {
		OAuth2Error oauth2Error = new OAuth2Error("unauthorized_client", "The client is not authorized",
				"https://tools.ietf.org/html/rfc6749#section-5.2");

		MockHttpOutputMessage outputMessage = new MockHttpOutputMessage();
		this.messageConverter.writeInternal(oauth2Error, outputMessage);
		String errorResponse = outputMessage.getBodyAsString();

		assertThat(errorResponse).contains("\"error\":\"unauthorized_client\"");
		assertThat(errorResponse).contains("\"error_description\":\"The client is not authorized\"");
		assertThat(errorResponse).contains("\"error_uri\":\"https://tools.ietf.org/html/rfc6749#section-5.2\"");
	}

	@Test
	public void writeInternalWhenConversionFailsThenThrowHttpMessageNotWritableException() {
		Converter errorParametersConverter = mock(Converter.class);
		given(errorParametersConverter.convert(any())).willThrow(RuntimeException.class);
		this.messageConverter.setErrorParametersConverter(errorParametersConverter);

		OAuth2Error oauth2Error = new OAuth2Error("unauthorized_client", "The client is not authorized",
				"https://tools.ietf.org/html/rfc6749#section-5.2");

		MockHttpOutputMessage outputMessage = new MockHttpOutputMessage();

		assertThatThrownBy(() -> this.messageConverter.writeInternal(oauth2Error, outputMessage))
				.isInstanceOf(HttpMessageNotWritableException.class)
				.hasMessageContaining("An error occurred writing the OAuth 2.0 Error");
	}

}
