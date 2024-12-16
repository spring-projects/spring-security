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

import org.springframework.http.RequestEntity;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.CollectionUtils;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

/**
 * An implementation of an {@link AbstractOAuth2AuthorizationGrantRequestEntityConverter}
 * that converts the provided {@link TokenExchangeGrantRequest} to a {@link RequestEntity}
 * representation of an OAuth 2.0 Access Token Request for the Token Exchange Grant.
 *
 * @author Steve Riesenberg
 * @since 6.3
 * @see AbstractOAuth2AuthorizationGrantRequestEntityConverter
 * @see TokenExchangeGrantRequest
 * @see RequestEntity
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc8693#section-1.1">Section
 * 1.1 Delegation vs. Impersonation Semantics</a>
 * @deprecated Use {@link DefaultOAuth2TokenRequestParametersConverter} instead
 */
@Deprecated(since = "6.4")
public class TokenExchangeGrantRequestEntityConverter
		extends AbstractOAuth2AuthorizationGrantRequestEntityConverter<TokenExchangeGrantRequest> {

	private static final String ACCESS_TOKEN_TYPE_VALUE = "urn:ietf:params:oauth:token-type:access_token";

	private static final String JWT_TOKEN_TYPE_VALUE = "urn:ietf:params:oauth:token-type:jwt";

	@Override
	protected MultiValueMap<String, String> createParameters(TokenExchangeGrantRequest grantRequest) {
		ClientRegistration clientRegistration = grantRequest.getClientRegistration();
		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
		parameters.add(OAuth2ParameterNames.GRANT_TYPE, grantRequest.getGrantType().getValue());
		parameters.add(OAuth2ParameterNames.REQUESTED_TOKEN_TYPE, ACCESS_TOKEN_TYPE_VALUE);
		OAuth2Token subjectToken = grantRequest.getSubjectToken();
		parameters.add(OAuth2ParameterNames.SUBJECT_TOKEN, subjectToken.getTokenValue());
		parameters.add(OAuth2ParameterNames.SUBJECT_TOKEN_TYPE, tokenType(subjectToken));
		OAuth2Token actorToken = grantRequest.getActorToken();
		if (actorToken != null) {
			parameters.add(OAuth2ParameterNames.ACTOR_TOKEN, actorToken.getTokenValue());
			parameters.add(OAuth2ParameterNames.ACTOR_TOKEN_TYPE, tokenType(actorToken));
		}
		if (!CollectionUtils.isEmpty(clientRegistration.getScopes())) {
			parameters.add(OAuth2ParameterNames.SCOPE,
					StringUtils.collectionToDelimitedString(clientRegistration.getScopes(), " "));
		}
		if (ClientAuthenticationMethod.CLIENT_SECRET_POST.equals(clientRegistration.getClientAuthenticationMethod())) {
			parameters.add(OAuth2ParameterNames.CLIENT_ID, clientRegistration.getClientId());
			parameters.add(OAuth2ParameterNames.CLIENT_SECRET, clientRegistration.getClientSecret());
		}
		return parameters;
	}

	private static String tokenType(OAuth2Token token) {
		return (token instanceof Jwt) ? JWT_TOKEN_TYPE_VALUE : ACCESS_TOKEN_TYPE_VALUE;
	}

}
