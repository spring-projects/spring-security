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

package org.springframework.security.authentication.apikey;

import java.time.Instant;

import org.springframework.security.core.AuthenticationException;

/**
 * Base class for API key authentication exception.
 *
 * @author Alexey Razinkov
 */
public abstract sealed class ApiKeyAuthenticationException extends AuthenticationException {

	private ApiKeyAuthenticationException() {
		super("API key authentication failed");
	}

	private ApiKeyAuthenticationException(final Throwable t) {
		super("API key authentication failed", t);
	}

	/**
	 * Thrown when failed to find stored API key with such ID.
	 */
	public static final class NotFound extends ApiKeyAuthenticationException {

		private final String apiKeyId;

		public NotFound(final String apiKeyId) {
			this.apiKeyId = apiKeyId;
		}

		public String getApiKeyId() {
			return this.apiKeyId;
		}

	}

	/**
	 * Thrown when API key is expired.
	 */
	public static final class Expired extends ApiKeyAuthenticationException {

		private final String apiKeyId;

		private final Instant expiredAt;

		private final Instant checkedAt;

		public Expired(final String apiKeyId, final Instant expiredAt, final Instant checkedAt) {
			this.apiKeyId = apiKeyId;
			this.expiredAt = expiredAt;
			this.checkedAt = checkedAt;
		}

		public String getApiKeyId() {
			return this.apiKeyId;
		}

		public Instant getExpiredAt() {
			return this.expiredAt;
		}

		public Instant getCheckedAt() {
			return this.checkedAt;
		}

	}

	/**
	 * Thrown when API key is expected as bearer token but no "Bearer" scheme found.
	 */
	public static final class MissingBearerScheme extends ApiKeyAuthenticationException {

	}

	/**
	 * Thrown when API key is expected as bearer token and "Bearer" scheme is present but
	 * token is missing.
	 */
	public static final class MissingBearerToken extends ApiKeyAuthenticationException {

	}

	/**
	 * Thrown when API key has invalid structure.
	 */
	public static final class Invalid extends ApiKeyAuthenticationException {

		private final String token;

		public Invalid(final String token, final Throwable cause) {
			super(cause);
			this.token = token;
		}

		public String getToken() {
			return this.token;
		}

	}

}
