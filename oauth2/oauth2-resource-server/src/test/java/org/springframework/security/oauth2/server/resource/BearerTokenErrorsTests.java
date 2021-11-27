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

package org.springframework.security.oauth2.server.resource;

import org.junit.jupiter.api.Test;

import org.springframework.http.HttpStatus;

import static org.assertj.core.api.Assertions.assertThat;

public class BearerTokenErrorsTests {

	@Test
	public void invalidRequestWhenMessageGivenThenBearerTokenErrorReturned() {
		String message = "message";
		BearerTokenError error = BearerTokenErrors.invalidRequest(message);
		assertThat(error.getErrorCode()).isSameAs(BearerTokenErrorCodes.INVALID_REQUEST);
		assertThat(error.getDescription()).isSameAs(message);
		assertThat(error.getHttpStatus()).isSameAs(HttpStatus.BAD_REQUEST);
		assertThat(error.getUri()).isEqualTo("https://tools.ietf.org/html/rfc6750#section-3.1");
	}

	@Test
	public void invalidRequestWhenInvalidMessageGivenThenDefaultBearerTokenErrorReturned() {
		String message = "has \"invalid\" chars";
		BearerTokenError error = BearerTokenErrors.invalidRequest(message);
		assertThat(error.getErrorCode()).isSameAs(BearerTokenErrorCodes.INVALID_REQUEST);
		assertThat(error.getDescription()).isEqualTo("Invalid request");
		assertThat(error.getHttpStatus()).isSameAs(HttpStatus.BAD_REQUEST);
		assertThat(error.getUri()).isEqualTo("https://tools.ietf.org/html/rfc6750#section-3.1");
	}

	@Test
	public void invalidTokenWhenMessageGivenThenBearerTokenErrorReturned() {
		String message = "message";
		BearerTokenError error = BearerTokenErrors.invalidToken(message);
		assertThat(error.getErrorCode()).isSameAs(BearerTokenErrorCodes.INVALID_TOKEN);
		assertThat(error.getDescription()).isSameAs(message);
		assertThat(error.getHttpStatus()).isSameAs(HttpStatus.UNAUTHORIZED);
		assertThat(error.getUri()).isEqualTo("https://tools.ietf.org/html/rfc6750#section-3.1");
	}

	@Test
	public void invalidTokenWhenInvalidMessageGivenThenDefaultBearerTokenErrorReturned() {
		String message = "has \"invalid\" chars";
		BearerTokenError error = BearerTokenErrors.invalidToken(message);
		assertThat(error.getErrorCode()).isSameAs(BearerTokenErrorCodes.INVALID_TOKEN);
		assertThat(error.getDescription()).isEqualTo("Invalid token");
		assertThat(error.getHttpStatus()).isSameAs(HttpStatus.UNAUTHORIZED);
		assertThat(error.getUri()).isEqualTo("https://tools.ietf.org/html/rfc6750#section-3.1");
	}

	@Test
	public void insufficientScopeWhenMessageGivenThenBearerTokenErrorReturned() {
		String message = "message";
		String scope = "scope";
		BearerTokenError error = BearerTokenErrors.insufficientScope(message, scope);
		assertThat(error.getErrorCode()).isSameAs(BearerTokenErrorCodes.INSUFFICIENT_SCOPE);
		assertThat(error.getDescription()).isSameAs(message);
		assertThat(error.getHttpStatus()).isSameAs(HttpStatus.FORBIDDEN);
		assertThat(error.getScope()).isSameAs(scope);
		assertThat(error.getUri()).isEqualTo("https://tools.ietf.org/html/rfc6750#section-3.1");
	}

	@Test
	public void insufficientScopeWhenInvalidMessageGivenThenDefaultBearerTokenErrorReturned() {
		String message = "has \"invalid\" chars";
		BearerTokenError error = BearerTokenErrors.insufficientScope(message, "scope");
		assertThat(error.getErrorCode()).isSameAs(BearerTokenErrorCodes.INSUFFICIENT_SCOPE);
		assertThat(error.getDescription()).isSameAs("Insufficient scope");
		assertThat(error.getHttpStatus()).isSameAs(HttpStatus.FORBIDDEN);
		assertThat(error.getScope()).isNull();
		assertThat(error.getUri()).isEqualTo("https://tools.ietf.org/html/rfc6750#section-3.1");
	}

}
