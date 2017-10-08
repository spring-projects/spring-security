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
package org.springframework.security.oauth2.core.endpoint;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * A representation of an <i>OAuth 2.0 Authorization Response</i> for the authorization code grant type.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1.2">Section 4.1.2 Authorization Response</a>
 */
public final class AuthorizationResponse {
	private String redirectUri;
	private String state;
	private String code;
	private OAuth2Error error;

	private AuthorizationResponse() {
	}

	public String getRedirectUri() {
		return this.redirectUri;
	}

	public String getState() {
		return this.state;
	}

	public String getCode() {
		return this.code;
	}

	public OAuth2Error getError() {
		return this.error;
	}

	public boolean statusOk() {
		return !this.statusError();
	}

	public boolean statusError() {
		return (this.error != null && this.error.getErrorCode() != null);
	}

	public static Builder success(String code) {
		Assert.hasText(code, "code cannot be empty");
		return new Builder().code(code);
	}

	public static Builder error(String errorCode) {
		Assert.hasText(errorCode, "errorCode cannot be empty");
		return new Builder().errorCode(errorCode);
	}

	public static class Builder {
		private String redirectUri;
		private String state;
		private String code;
		private String errorCode;
		private String errorDescription;
		private String errorUri;

		private Builder() {
		}

		public Builder redirectUri(String redirectUri) {
			this.redirectUri = redirectUri;
			return this;
		}

		public Builder state(String state) {
			this.state = state;
			return this;
		}

		public Builder code(String code) {
			this.code = code;
			return this;
		}

		public Builder errorCode(String errorCode) {
			this.errorCode = errorCode;
			return this;
		}

		public Builder errorDescription(String errorDescription) {
			this.errorDescription = errorDescription;
			return this;
		}

		public Builder errorUri(String errorUri) {
			this.errorUri = errorUri;
			return this;
		}

		public AuthorizationResponse build() {
			if (StringUtils.hasText(this.code) && StringUtils.hasText(this.errorCode)) {
				throw new IllegalArgumentException("code and errorCode cannot both be set");
			}
			Assert.hasText(this.redirectUri, "redirectUri cannot be empty");

			AuthorizationResponse authorizationResponse = new AuthorizationResponse();
			authorizationResponse.redirectUri = this.redirectUri;
			authorizationResponse.state = this.state;
			if (StringUtils.hasText(this.code)) {
				authorizationResponse.code = this.code;
			} else {
				authorizationResponse.error = new OAuth2Error(
					this.errorCode, this.errorDescription, this.errorUri);
			}
			return authorizationResponse;
		}
	}
}
