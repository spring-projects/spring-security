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

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

import java.io.Serializable;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * A representation of an <i>OAuth 2.0 Authorization Request</i>
 * for the authorization code grant type or implicit grant type.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see AuthorizationGrantType
 * @see ResponseType
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1.1">Section 4.1.1 Authorization Code Grant Request</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.2.1">Section 4.2.1 Implicit Grant Request</a>
 */
public final class AuthorizationRequestAttributes implements Serializable {
	private String authorizeUri;
	private AuthorizationGrantType authorizationGrantType;
	private ResponseType responseType;
	private String clientId;
	private String redirectUri;
	private Set<String> scope;
	private String state;

	private AuthorizationRequestAttributes() {
	}

	public String getAuthorizeUri() {
		return this.authorizeUri;
	}

	public AuthorizationGrantType getGrantType() {
		return this.authorizationGrantType;
	}

	public ResponseType getResponseType() {
		return this.responseType;
	}

	public String getClientId() {
		return this.clientId;
	}

	public String getRedirectUri() {
		return this.redirectUri;
	}

	public Set<String> getScope() {
		return this.scope;
	}

	public String getState() {
		return this.state;
	}

	public static Builder withAuthorizationCode() {
		return new Builder(AuthorizationGrantType.AUTHORIZATION_CODE);
	}

	public static class Builder {
		private final AuthorizationRequestAttributes authorizationRequest;

		private Builder(AuthorizationGrantType authorizationGrantType) {
			Assert.notNull(authorizationGrantType, "authorizationGrantType cannot be null");
			this.authorizationRequest = new AuthorizationRequestAttributes();
			this.authorizationRequest.authorizationGrantType = authorizationGrantType;
			if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(authorizationGrantType)) {
				this.authorizationRequest.responseType = ResponseType.CODE;
			}
		}

		public Builder authorizeUri(String authorizeUri) {
			this.authorizationRequest.authorizeUri = authorizeUri;
			return this;
		}

		public Builder clientId(String clientId) {
			this.authorizationRequest.clientId = clientId;
			return this;
		}

		public Builder redirectUri(String redirectUri) {
			this.authorizationRequest.redirectUri = redirectUri;
			return this;
		}

		public Builder scope(Set<String> scope) {
			this.authorizationRequest.scope = Collections.unmodifiableSet(
				CollectionUtils.isEmpty(scope) ? Collections.emptySet() : new LinkedHashSet<>(scope));
			return this;
		}

		public Builder state(String state) {
			this.authorizationRequest.state = state;
			return this;
		}

		public AuthorizationRequestAttributes build() {
			Assert.hasText(this.authorizationRequest.clientId, "clientId cannot be empty");
			Assert.hasText(this.authorizationRequest.authorizeUri, "authorizeUri cannot be empty");
			return this.authorizationRequest;
		}
	}
}
