/*
 * Copyright 2002-2021 the original author or authors.
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
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

/**
 * An implementation of an {@link AbstractOAuth2AuthorizationGrantRequestEntityConverter}
 * that converts the provided {@link OAuth2AuthorizationCodeGrantRequest} to a
 * {@link RequestEntity} representation of an OAuth 2.0 Access Token Request for the
 * Authorization Code Grant.
 *
 * @author Joe Grandja
 * @since 5.1
 * @see AbstractOAuth2AuthorizationGrantRequestEntityConverter
 * @see OAuth2AuthorizationCodeGrantRequest
 * @see RequestEntity
 */
public class OAuth2AuthorizationCodeGrantRequestEntityConverter
		extends AbstractOAuth2AuthorizationGrantRequestEntityConverter<OAuth2AuthorizationCodeGrantRequest> {

	@Override
	protected MultiValueMap<String, String> createParameters(
			OAuth2AuthorizationCodeGrantRequest authorizationCodeGrantRequest) {
		ClientRegistration clientRegistration = authorizationCodeGrantRequest.getClientRegistration();
		OAuth2AuthorizationExchange authorizationExchange = authorizationCodeGrantRequest.getAuthorizationExchange();
		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
		parameters.add(OAuth2ParameterNames.GRANT_TYPE, authorizationCodeGrantRequest.getGrantType().getValue());
		parameters.add(OAuth2ParameterNames.CODE, authorizationExchange.getAuthorizationResponse().getCode());
		String redirectUri = authorizationExchange.getAuthorizationRequest().getRedirectUri();
		String codeVerifier = authorizationExchange.getAuthorizationRequest()
				.getAttribute(PkceParameterNames.CODE_VERIFIER);
		if (redirectUri != null) {
			parameters.add(OAuth2ParameterNames.REDIRECT_URI, redirectUri);
		}
		if (!ClientAuthenticationMethod.CLIENT_SECRET_BASIC.equals(clientRegistration.getClientAuthenticationMethod())
				&& !ClientAuthenticationMethod.BASIC.equals(clientRegistration.getClientAuthenticationMethod())) {
			parameters.add(OAuth2ParameterNames.CLIENT_ID, clientRegistration.getClientId());
		}
		if (ClientAuthenticationMethod.CLIENT_SECRET_POST.equals(clientRegistration.getClientAuthenticationMethod())
				|| ClientAuthenticationMethod.POST.equals(clientRegistration.getClientAuthenticationMethod())) {
			parameters.add(OAuth2ParameterNames.CLIENT_SECRET, clientRegistration.getClientSecret());
		}
		if (codeVerifier != null) {
			parameters.add(PkceParameterNames.CODE_VERIFIER, codeVerifier);
		}
		return parameters;
	}

}
