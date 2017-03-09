/*
 * Copyright 2012-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.core;

import org.springframework.http.HttpStatus;

import java.net.URI;
import java.util.Arrays;
import java.util.Optional;

/**
 * @author Joe Grandja
 */
public final class OAuth2Error {
	private final ErrorCode errorCode;
	private final String description;
	private final URI uri;
	private final HttpStatus statusCode;

	public enum ErrorCode {

		// Standard Errors
		INVALID_REQUEST("invalid_request", HttpStatus.BAD_REQUEST),
		INVALID_CLIENT("invalid_client", HttpStatus.UNAUTHORIZED),
		INVALID_GRANT("invalid_grant", HttpStatus.BAD_REQUEST),
		UNAUTHORIZED_CLIENT("unauthorized_client", HttpStatus.BAD_REQUEST),
		UNSUPPORTED_GRANT_TYPE("unsupported_grant_type", HttpStatus.BAD_REQUEST),
		INVALID_SCOPE("invalid_scope", HttpStatus.BAD_REQUEST),

		// Non-standard Errors
		INVALID_TOKEN_RESPONSE("invalid_token_response", HttpStatus.UNPROCESSABLE_ENTITY),
		INVALID_USER_INFO_RESPONSE("invalid_user_info_response", HttpStatus.UNPROCESSABLE_ENTITY),
		AUTHORIZATION_REQUEST_NOT_FOUND("authorization_request_not_found", HttpStatus.UNAUTHORIZED),
		INVALID_STATE_PARAMETER("invalid_state_parameter", HttpStatus.UNAUTHORIZED),
		INVALID_REDIRECT_URI_PARAMETER("invalid_redirect_uri_parameter", HttpStatus.UNAUTHORIZED),
		UNKNOWN_ERROR_CODE("unknown_error_code", HttpStatus.BAD_REQUEST);

		private String errorCode;
		private HttpStatus mappedStatusCode;

		ErrorCode(String errorCode, HttpStatus mappedStatusCode) {
			this.errorCode = errorCode;
			this.mappedStatusCode = mappedStatusCode;
		}

		public static ErrorCode fromValue(String value) {
			Optional<ErrorCode> errorCode = Arrays.asList(values()).stream()
					.filter(e -> e.errorCode.equalsIgnoreCase(value)).findFirst();
			return errorCode.isPresent() ? errorCode.get() : null;
		}

		@Override
		public String toString() {
			return this.errorCode;
		}
	}

	private OAuth2Error(ErrorCode errorCode, String description, URI uri, HttpStatus statusCode) {
		this.errorCode = errorCode;
		this.description = description;
		this.uri = uri;
		this.statusCode = statusCode;
	}

	public ErrorCode getErrorCode() {
		return this.errorCode;
	}

	public String getDescription() {
		return this.description;
	}

	public URI getUri() {
		return this.uri;
	}

	public HttpStatus getStatusCode() {
		return this.statusCode;
	}

	public String getErrorMessage() {
		return "[" + this.getErrorCode().toString() + "] " +
				(this.getDescription() != null ? this.getDescription() : "");
	}

	public static OAuth2Error invalidTokenResponse() {
		return valueOf(ErrorCode.INVALID_TOKEN_RESPONSE.errorCode);
	}

	public static OAuth2Error invalidUserInfoResponse() {
		return valueOf(ErrorCode.INVALID_USER_INFO_RESPONSE.errorCode);
	}

	public static OAuth2Error authorizationRequestNotFound() {
		return valueOf(ErrorCode.AUTHORIZATION_REQUEST_NOT_FOUND.errorCode);
	}

	public static OAuth2Error invalidStateParameter() {
		return valueOf(ErrorCode.INVALID_STATE_PARAMETER.errorCode);
	}

	public static OAuth2Error invalidRedirectUriParameter() {
		return valueOf(ErrorCode.INVALID_REDIRECT_URI_PARAMETER.errorCode);
	}

	public static OAuth2Error valueOf(String errorCode) {
		return valueOf(errorCode, null, null);
	}

	public static OAuth2Error valueOf(String errorCode, String description, URI uri) {
		ErrorCode errCode = ErrorCode.fromValue(errorCode);
		if (errCode == null) {
			errCode = ErrorCode.UNKNOWN_ERROR_CODE;
		}
		return new OAuth2Error(errCode, description, uri, errCode.mappedStatusCode);
	}
}