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

import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

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
public final class AuthorizationRequest implements Serializable {
	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;
	private String authorizationUri;
	private AuthorizationGrantType authorizationGrantType;
	private ResponseType responseType;
	private String clientId;
	private String redirectUri;
	private Set<String> scopes;
	private String state;
	private Map<String,Object> additionalParameters;

	private AuthorizationRequest() {
	}

	public String getAuthorizationUri() {
		return this.authorizationUri;
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

	public Set<String> getScopes() {
		return this.scopes;
	}

	public String getState() {
		return this.state;
	}

	public Map<String, Object> getAdditionalParameters() {
		return this.additionalParameters;
	}

	public static Builder authorizationCode() {
		return new Builder(AuthorizationGrantType.AUTHORIZATION_CODE);
	}

	public static Builder implicit() {
		return new Builder(AuthorizationGrantType.IMPLICIT);
	}

	public static class Builder {
		private String authorizationUri;
		private AuthorizationGrantType authorizationGrantType;
		private ResponseType responseType;
		private String clientId;
		private String redirectUri;
		private Set<String> scopes;
		private String state;
		private Map<String,Object> additionalParameters;

		private Builder(AuthorizationGrantType authorizationGrantType) {
			Assert.notNull(authorizationGrantType, "authorizationGrantType cannot be null");
			this.authorizationGrantType = authorizationGrantType;
			if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(authorizationGrantType)) {
				this.responseType = ResponseType.CODE;
			} else if (AuthorizationGrantType.IMPLICIT.equals(authorizationGrantType)) {
				this.responseType = ResponseType.TOKEN;
			}
		}

		public Builder authorizationUri(String authorizationUri) {
			this.authorizationUri = authorizationUri;
			return this;
		}

		public Builder clientId(String clientId) {
			this.clientId = clientId;
			return this;
		}

		public Builder redirectUri(String redirectUri) {
			this.redirectUri = redirectUri;
			return this;
		}

		public Builder scope(String... scope) {
			if (scope != null && scope.length > 0) {
				return this.scopes(Arrays.stream(scope).collect(
					Collectors.toCollection(LinkedHashSet::new)));
			}
			return this;
		}

		public Builder scopes(Set<String> scopes) {
			this.scopes = scopes;
			return this;
		}

		public Builder state(String state) {
			this.state = state;
			return this;
		}

		public Builder additionalParameters(Map<String,Object> additionalParameters) {
			this.additionalParameters = additionalParameters;
			return this;
		}

		public AuthorizationRequest build() {
			Assert.hasText(this.authorizationUri, "authorizationUri cannot be empty");
			Assert.hasText(this.clientId, "clientId cannot be empty");
			if (AuthorizationGrantType.IMPLICIT.equals(this.authorizationGrantType)) {
				Assert.hasText(this.redirectUri, "redirectUri cannot be empty");
			}

			AuthorizationRequest authorizationRequest = new AuthorizationRequest();
			authorizationRequest.authorizationUri = this.authorizationUri;
			authorizationRequest.authorizationGrantType = this.authorizationGrantType;
			authorizationRequest.responseType = this.responseType;
			authorizationRequest.clientId = this.clientId;
			authorizationRequest.redirectUri = this.redirectUri;
			authorizationRequest.state = this.state;
			authorizationRequest.scopes = Collections.unmodifiableSet(
				CollectionUtils.isEmpty(this.scopes) ?
					Collections.emptySet() : new LinkedHashSet<>(this.scopes));
			authorizationRequest.additionalParameters = Collections.unmodifiableMap(
				CollectionUtils.isEmpty(this.additionalParameters) ?
					Collections.emptyMap() : new LinkedHashMap<>(this.additionalParameters));
			return authorizationRequest;
		}
	}
}
