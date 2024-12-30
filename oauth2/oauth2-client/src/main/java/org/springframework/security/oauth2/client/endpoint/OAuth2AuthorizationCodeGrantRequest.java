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
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.util.Assert;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

/**
 * An OAuth 2.0 Authorization Code Grant request that holds an Authorization Code
 * credential, which was granted by the Resource Owner to the
 * {@link #getClientRegistration() Client}.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see AbstractOAuth2AuthorizationGrantRequest
 * @see ClientRegistration
 * @see OAuth2AuthorizationExchange
 * @see <a target="_blank" href=
 * "https://tools.ietf.org/html/rfc6749#section-1.3.1">Section 1.3.1 Authorization Code
 * Grant</a>
 */
public class OAuth2AuthorizationCodeGrantRequest extends AbstractOAuth2AuthorizationGrantRequest {

	private final OAuth2AuthorizationExchange authorizationExchange;

	/**
	 * Constructs an {@code OAuth2AuthorizationCodeGrantRequest} using the provided
	 * parameters.
	 * @param clientRegistration the client registration
	 * @param authorizationExchange the authorization exchange
	 */
	public OAuth2AuthorizationCodeGrantRequest(ClientRegistration clientRegistration,
			OAuth2AuthorizationExchange authorizationExchange) {
		super(AuthorizationGrantType.AUTHORIZATION_CODE, clientRegistration);
		Assert.notNull(authorizationExchange, "authorizationExchange cannot be null");
		this.authorizationExchange = authorizationExchange;
	}

	/**
	 * Returns the {@link OAuth2AuthorizationExchange authorization exchange}.
	 * @return the {@link OAuth2AuthorizationExchange}
	 */
	public OAuth2AuthorizationExchange getAuthorizationExchange() {
		return this.authorizationExchange;
	}

	/**
	 * Populate default parameters for the Authorization Code Grant.
	 * @param grantRequest the authorization grant request
	 * @return a {@link MultiValueMap} of the parameters used in the OAuth 2.0 Access
	 * Token Request body
	 */
	static MultiValueMap<String, String> defaultParameters(OAuth2AuthorizationCodeGrantRequest grantRequest) {
		OAuth2AuthorizationExchange authorizationExchange = grantRequest.getAuthorizationExchange();
		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
		parameters.set(OAuth2ParameterNames.CODE, authorizationExchange.getAuthorizationResponse().getCode());
		String redirectUri = authorizationExchange.getAuthorizationRequest().getRedirectUri();
		if (redirectUri != null) {
			parameters.set(OAuth2ParameterNames.REDIRECT_URI, redirectUri);
		}
		String codeVerifier = authorizationExchange.getAuthorizationRequest()
			.getAttribute(PkceParameterNames.CODE_VERIFIER);
		if (codeVerifier != null) {
			parameters.set(PkceParameterNames.CODE_VERIFIER, codeVerifier);
		}
		return parameters;
	}

}
