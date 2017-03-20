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

import org.springframework.util.Assert;

/**
 * A representation of an <i>OAuth 2.0 Access Token Request</i> for the authorization code grant type.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1.3">Section 4.1.3 Access Token Request</a>
 */
public final class AuthorizationCodeTokenRequestAttributes {
	private String code;
	private String clientId;
	private String redirectUri;

	private AuthorizationCodeTokenRequestAttributes() {
	}

	public String getCode() {
		return this.code;
	}

	public String getClientId() {
		return this.clientId;
	}

	public String getRedirectUri() {
		return this.redirectUri;
	}

	public static Builder withCode(String code) {
		return new Builder(code);
	}

	public static class Builder {
		private final AuthorizationCodeTokenRequestAttributes authorizationCodeTokenRequest;

		private Builder(String code) {
			Assert.hasText(code, "code cannot be empty");
			this.authorizationCodeTokenRequest = new AuthorizationCodeTokenRequestAttributes();
			this.authorizationCodeTokenRequest.code = code;
		}

		public Builder clientId(String clientId) {
			Assert.hasText(clientId, "clientId cannot be empty");
			this.authorizationCodeTokenRequest.clientId = clientId;
			return this;
		}

		public Builder redirectUri(String redirectUri) {
			Assert.hasText(redirectUri, "redirectUri cannot be empty");
			this.authorizationCodeTokenRequest.redirectUri = redirectUri;
			return this;
		}

		public AuthorizationCodeTokenRequestAttributes build() {
			return this.authorizationCodeTokenRequest;
		}
	}
}
