/*
 * Copyright 2002-2019 the original author or authors.
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
package org.springframework.security.test.oauth2.reactive.server;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * @author Jérôme Wacongne &lt;ch4mp@c4-soft.com&gt;
 * @since 5.2.0
 */
public class OAuth2SecurityMockServerConfigurers {

	public static JwtMutator mockJwt() {
		return new JwtMutator();
	}

	public static JwtMutator mockJwt(final Jwt jwt) {
		return mockJwt().jwt(jwt);
	}

	public static AccessTokenMutator mockAccessToken() {
		return new AccessTokenMutator();
	}

	public static AccessTokenMutator mockAccessToken(final OAuth2AccessToken token) {
		return mockAccessToken().accessToken(token);
	}

	public static OidcIdTokenMutator mockOidcId(final AuthorizationGrantType authorizationRequestGrantType) {
		return new OidcIdTokenMutator(authorizationRequestGrantType);
	}

	public static OidcIdTokenMutator mockOidcId() {
		return mockOidcId(AuthorizationGrantType.AUTHORIZATION_CODE);
	}

	public static OidcIdTokenMutator
			mockOidcId(final AuthorizationGrantType requestAuthorizationRequestGrantType, final OidcIdToken token) {
		return mockOidcId(requestAuthorizationRequestGrantType).token(token);
	}

	public static OidcIdTokenMutator mockOidcId(final OidcIdToken token) {
		return mockOidcId().token(token);
	}

}
