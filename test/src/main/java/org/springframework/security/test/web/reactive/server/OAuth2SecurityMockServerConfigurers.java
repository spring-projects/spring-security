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
package org.springframework.security.test.web.reactive.server;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.OAuth2IntrospectionAuthenticationToken;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 * @since 5.2
 */
public class OAuth2SecurityMockServerConfigurers {
	/**
	 * Updates the ServerWebExchange to establish a {@link SecurityContext} that has a
	 * {@link JwtAuthenticationToken} for the
	 * {@link Authentication} and a {@link Jwt} for the
	 * {@link Authentication#getPrincipal()}. All details are
	 * declarative and do not require the JWT to be valid.
	 *
	 * @return the {@link JwtMutator} to further configure or use
	 */
	public static JwtMutator mockJwt() {
		return new JwtMutator();
	}

	/**
	 * Updates the ServerWebExchange to establish a {@link SecurityContext} that has a
	 * {@link JwtAuthenticationToken} for the
	 * {@link Authentication} and a {@link Jwt} for the
	 * {@link Authentication#getPrincipal()}. All details are
	 * declarative and do not require the JWT to be valid.
	 *
	 * @param jwt a complete JWT to extract and apply token value, subject, authorities and claims configuration
	 * @return the {@link JwtMutator} to further configure or use
	 */
	public static JwtMutator mockJwt(final Jwt jwt) {
		return mockJwt().jwt(jwt);
	}

	/**
	 * Updates the ServerWebExchange to establish a {@link SecurityContext} that has an
	 * {@link OAuth2IntrospectionAuthenticationToken} for the
	 * {@link Authentication} and an {@link OAuth2AccessToken} for the
	 * {@link Authentication#getPrincipal()}. All details are
	 * declarative and do not require the OAuth2AccessToken to be valid.
	 *
	 * @return the {@link AccessTokenMutator} to further configure or use
	 */
	public static AccessTokenMutator mockAccessToken() {
		return new AccessTokenMutator();
	}

	/**
	 * Updates the ServerWebExchange to establish a {@link SecurityContext} that has an
	 * {@link OAuth2LoginAuthenticationToken} for the
	 * {@link Authentication} and a {@link DefaultOidcUser} for the
	 * {@link Authentication#getPrincipal()}. All details are
	 * declarative and do not require the DefaultOidcUser to be valid or even user to exist.
	 *
	 * @param authorizationGrantType authorization request grant-type 
	 * @return the {@link OidcIdTokenMutator} to further configure or use
	 */
	public static OidcIdTokenMutator mockOidcId(final AuthorizationGrantType authorizationRequestGrantType) {
		return new OidcIdTokenMutator(authorizationRequestGrantType);
	}

	/**
	 * Updates the ServerWebExchange to establish a {@link SecurityContext} that has an
	 * {@link OAuth2LoginAuthenticationToken} for the
	 * {@link Authentication} and a {@link DefaultOidcUser} for the
	 * {@link Authentication#getPrincipal()}. All details are
	 * declarative and do not require the DefaultOidcUser to be valid or even user to exist.
	 *
	 * @return the {@link OidcIdTokenMutator} to further configure or use
	 */
	public static OidcIdTokenMutator mockOidcId() {
		return mockOidcId(AuthorizationGrantType.AUTHORIZATION_CODE);
	}
}
