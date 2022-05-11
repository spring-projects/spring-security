/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.oauth2.client.http;

import java.io.IOException;

import org.junit.jupiter.api.Test;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.mock.http.MockHttpInputMessage;
import org.springframework.mock.http.client.MockClientHttpResponse;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link OAuth2ErrorResponseErrorHandler}.
 *
 * @author Joe Grandja
 */
public class OAuth2ErrorResponseErrorHandlerTests {

	private OAuth2ErrorResponseErrorHandler errorHandler = new OAuth2ErrorResponseErrorHandler();

	@Test
	public void handleErrorWhenErrorResponseBodyThenHandled() {
		// @formatter:off
		String errorResponse = "{\n"
				+ "   \"error\": \"unauthorized_client\",\n"
				+ "   \"error_description\": \"The client is not authorized\"\n"
				+ "}\n";
		// @formatter:on
		MockClientHttpResponse response = new MockClientHttpResponse(errorResponse.getBytes(), HttpStatus.BAD_REQUEST);
		assertThatExceptionOfType(OAuth2AuthorizationException.class)
				.isThrownBy(() -> this.errorHandler.handleError(response))
				.withMessage("[unauthorized_client] The client is not authorized");
	}

	@Test
	public void handleErrorWhenOAuth2ErrorConverterSetThenCalled() throws IOException {
		HttpMessageConverter<OAuth2Error> oauth2ErrorConverter = mock(HttpMessageConverter.class);
		this.errorHandler.setErrorConverter(oauth2ErrorConverter);
		// @formatter:off
		String errorResponse = "{\n"
				+ "   \"errorCode\": \"unauthorized_client\",\n"
				+ "   \"errorSummary\": \"The client is not authorized\"\n"
				+ "}\n";
		// @formatter:on
		MockClientHttpResponse response = new MockClientHttpResponse(errorResponse.getBytes(), HttpStatus.BAD_REQUEST);
		given(oauth2ErrorConverter.read(any(), any()))
				.willReturn(new OAuth2Error("unauthorized_client", "The client is not authorized", null));

		assertThatExceptionOfType(OAuth2AuthorizationException.class)
				.isThrownBy(() -> this.errorHandler.handleError(response))
				.withMessage("[unauthorized_client] The client is not authorized");
		verify(oauth2ErrorConverter).read(eq(OAuth2Error.class), eq(response));
	}

	@Test
	public void handleErrorWhenErrorResponseWwwAuthenticateHeaderThenHandled() {
		String wwwAuthenticateHeader = "Bearer realm=\"auth-realm\" error=\"insufficient_scope\" error_description=\"The access token expired\"";
		MockClientHttpResponse response = new MockClientHttpResponse(new byte[0], HttpStatus.BAD_REQUEST);
		response.getHeaders().add(HttpHeaders.WWW_AUTHENTICATE, wwwAuthenticateHeader);
		assertThatExceptionOfType(OAuth2AuthorizationException.class)
				.isThrownBy(() -> this.errorHandler.handleError(response))
				.withMessage("[insufficient_scope] The access token expired");
	}

	@Test
	public void handleErrorWhenErrorResponseWithInvalidWwwAuthenticateHeaderThenHandled() {
		String invalidWwwAuthenticateHeader = "Unauthorized";
		MockClientHttpResponse response = new MockClientHttpResponse(new byte[0], HttpStatus.BAD_REQUEST);
		response.getHeaders().add(HttpHeaders.WWW_AUTHENTICATE, invalidWwwAuthenticateHeader);
		assertThatExceptionOfType(OAuth2AuthorizationException.class)
				.isThrownBy(() -> this.errorHandler.handleError(response)).withMessage("[server_error] ");
	}

	@Test
	public void handleErrorWhenErrorResponseWithInvalidStatusCodeThenHandled() {
		CustomMockClientHttpResponse response = new CustomMockClientHttpResponse(new byte[0], 596);
		assertThatExceptionOfType(IllegalArgumentException.class)
				.isThrownBy(() -> this.errorHandler.handleError(response))
				.withMessage("No matching constant for [596]");
	}

	private static final class CustomMockClientHttpResponse extends MockHttpInputMessage implements ClientHttpResponse {

		private final int statusCode;

		private CustomMockClientHttpResponse(byte[] content, int statusCode) {
			super(content);
			this.statusCode = statusCode;
		}

		@Override
		public HttpStatus getStatusCode() throws IOException {
			return HttpStatus.valueOf(getRawStatusCode());
		}

		@Override
		public int getRawStatusCode() {
			return this.statusCode;
		}

		@Override
		public String getStatusText() throws IOException {
			HttpStatus httpStatus = HttpStatus.resolve(this.statusCode);
			return (httpStatus != null) ? httpStatus.getReasonPhrase() : "";
		}

		@Override
		public void close() {
			try {
				getBody().close();
			}
			catch (IOException ex) {
				// ignore
			}
		}

	}

}
