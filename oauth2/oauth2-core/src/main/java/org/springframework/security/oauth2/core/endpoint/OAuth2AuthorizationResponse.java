/*
 * Copyright 2002-2017 the original author or authors.
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
package org.springframework.security.oauth2.core.endpoint;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * A representation of an OAuth 2.0 Authorization Response for the authorization code
 * grant type.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see OAuth2Error
 * @see <a target="_blank" href=
 * "https://tools.ietf.org/html/rfc6749#section-4.1.2">Section 4.1.2 Authorization
 * Response</a>
 */
public final class OAuth2AuthorizationResponse {

	private String redirectUri;

	private String state;

	private String code;

	private OAuth2Error error;

	private OAuth2AuthorizationResponse() {
	}

	/**
	 * Returns the uri where the response was redirected to.
	 * @return the uri where the response was redirected to
	 */
	public String getRedirectUri() {
		return this.redirectUri;
	}

	/**
	 * Returns the state.
	 * @return the state
	 */
	public String getState() {
		return this.state;
	}

	/**
	 * Returns the authorization code.
	 * @return the authorization code
	 */
	public String getCode() {
		return this.code;
	}

	/**
	 * Returns the {@link OAuth2Error OAuth 2.0 Error} if the Authorization Request
	 * failed, otherwise {@code null}.
	 * @return the {@link OAuth2Error} if the Authorization Request failed, otherwise
	 * {@code null}
	 */
	public OAuth2Error getError() {
		return this.error;
	}

	/**
	 * Returns {@code true} if the Authorization Request succeeded, otherwise
	 * {@code false}.
	 * @return {@code true} if the Authorization Request succeeded, otherwise
	 * {@code false}
	 */
	public boolean statusOk() {
		return !this.statusError();
	}

	/**
	 * Returns {@code true} if the Authorization Request failed, otherwise {@code false}.
	 * @return {@code true} if the Authorization Request failed, otherwise {@code false}
	 */
	public boolean statusError() {
		return (this.error != null && this.error.getErrorCode() != null);
	}

	/**
	 * Returns a new {@link Builder}, initialized with the authorization code.
	 * @param code the authorization code
	 * @return the {@link Builder}
	 */
	public static Builder success(String code) {
		Assert.hasText(code, "code cannot be empty");
		return new Builder().code(code);
	}

	/**
	 * Returns a new {@link Builder}, initialized with the error code.
	 * @param errorCode the error code
	 * @return the {@link Builder}
	 */
	public static Builder error(String errorCode) {
		Assert.hasText(errorCode, "errorCode cannot be empty");
		return new Builder().errorCode(errorCode);
	}

	/**
	 * A builder for {@link OAuth2AuthorizationResponse}.
	 */
	public static class Builder {

		private String redirectUri;

		private String state;

		private String code;

		private String errorCode;

		private String errorDescription;

		private String errorUri;

		private Builder() {
		}

		/**
		 * Sets the uri where the response was redirected to.
		 * @param redirectUri the uri where the response was redirected to
		 * @return the {@link Builder}
		 */
		public Builder redirectUri(String redirectUri) {
			this.redirectUri = redirectUri;
			return this;
		}

		/**
		 * Sets the state.
		 * @param state the state
		 * @return the {@link Builder}
		 */
		public Builder state(String state) {
			this.state = state;
			return this;
		}

		/**
		 * Sets the authorization code.
		 * @param code the authorization code
		 * @return the {@link Builder}
		 */
		public Builder code(String code) {
			this.code = code;
			return this;
		}

		/**
		 * Sets the error code.
		 * @param errorCode the error code
		 * @return the {@link Builder}
		 */
		public Builder errorCode(String errorCode) {
			this.errorCode = errorCode;
			return this;
		}

		/**
		 * Sets the error description.
		 * @param errorDescription the error description
		 * @return the {@link Builder}
		 */
		public Builder errorDescription(String errorDescription) {
			this.errorDescription = errorDescription;
			return this;
		}

		/**
		 * Sets the error uri.
		 * @param errorUri the error uri
		 * @return the {@link Builder}
		 */
		public Builder errorUri(String errorUri) {
			this.errorUri = errorUri;
			return this;
		}

		/**
		 * Builds a new {@link OAuth2AuthorizationResponse}.
		 * @return a {@link OAuth2AuthorizationResponse}
		 */
		public OAuth2AuthorizationResponse build() {
			if (StringUtils.hasText(this.code) && StringUtils.hasText(this.errorCode)) {
				throw new IllegalArgumentException("code and errorCode cannot both be set");
			}
			Assert.hasText(this.redirectUri, "redirectUri cannot be empty");

			OAuth2AuthorizationResponse authorizationResponse = new OAuth2AuthorizationResponse();
			authorizationResponse.redirectUri = this.redirectUri;
			authorizationResponse.state = this.state;
			if (StringUtils.hasText(this.code)) {
				authorizationResponse.code = this.code;
			}
			else {
				authorizationResponse.error = new OAuth2Error(this.errorCode, this.errorDescription, this.errorUri);
			}
			return authorizationResponse;
		}

	}

}
