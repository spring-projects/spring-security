/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.oauth2.client.endpoint;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

/**
 * A JWT Bearer Grant request that holds a {@link Jwt} assertion.
 *
 * @author Joe Grandja
 * @since 5.5
 * @see AbstractOAuth2AuthorizationGrantRequest
 * @see ClientRegistration
 * @see Jwt
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7523#section-2.1">Section
 * 2.1 Using JWTs as Authorization Grants</a>
 */
public class JwtBearerGrantRequest extends AbstractOAuth2AuthorizationGrantRequest {

	private final Jwt jwt;

	/**
	 * Constructs a {@code JwtBearerGrantRequest} using the provided parameters.
	 * @param clientRegistration the client registration
	 * @param jwt the JWT assertion
	 */
	public JwtBearerGrantRequest(ClientRegistration clientRegistration, Jwt jwt) {
		super(AuthorizationGrantType.JWT_BEARER, clientRegistration);
		Assert.isTrue(AuthorizationGrantType.JWT_BEARER.equals(clientRegistration.getAuthorizationGrantType()),
				"clientRegistration.authorizationGrantType must be AuthorizationGrantType.JWT_BEARER");
		Assert.notNull(jwt, "jwt cannot be null");
		this.jwt = jwt;
	}

	/**
	 * Returns the {@link Jwt JWT} assertion.
	 * @return the {@link Jwt} assertion
	 */
	public Jwt getJwt() {
		return this.jwt;
	}

	/**
	 * Populate default parameters for the JWT Bearer Grant.
	 * @param grantRequest the authorization grant request
	 * @return a {@link MultiValueMap} of the parameters used in the OAuth 2.0 Access
	 * Token Request body
	 */
	static MultiValueMap<String, String> defaultParameters(JwtBearerGrantRequest grantRequest) {
		ClientRegistration clientRegistration = grantRequest.getClientRegistration();
		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
		if (!CollectionUtils.isEmpty(clientRegistration.getScopes())) {
			parameters.set(OAuth2ParameterNames.SCOPE,
					StringUtils.collectionToDelimitedString(clientRegistration.getScopes(), " "));
		}
		parameters.set(OAuth2ParameterNames.ASSERTION, grantRequest.getJwt().getTokenValue());
		return parameters;
	}

}
