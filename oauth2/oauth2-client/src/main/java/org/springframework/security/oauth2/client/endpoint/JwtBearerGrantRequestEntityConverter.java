/*
 * Copyright 2002-2022 the original author or authors.
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
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.CollectionUtils;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

/**
 * An implementation of an {@link AbstractOAuth2AuthorizationGrantRequestEntityConverter}
 * that converts the provided {@link JwtBearerGrantRequest} to a {@link RequestEntity}
 * representation of an OAuth 2.0 Access Token Request for the JWT Bearer Grant.
 *
 * @author Joe Grandja
 * @since 5.5
 * @see AbstractOAuth2AuthorizationGrantRequestEntityConverter
 * @see JwtBearerGrantRequest
 * @see RequestEntity
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7523#section-2.1">Section
 * 2.1 Using JWTs as Authorization Grants</a>
 */
public class JwtBearerGrantRequestEntityConverter
		extends AbstractOAuth2AuthorizationGrantRequestEntityConverter<JwtBearerGrantRequest> {

	@Override
	protected MultiValueMap<String, String> createParameters(JwtBearerGrantRequest jwtBearerGrantRequest) {
		ClientRegistration clientRegistration = jwtBearerGrantRequest.getClientRegistration();
		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
		parameters.add(OAuth2ParameterNames.GRANT_TYPE, jwtBearerGrantRequest.getGrantType().getValue());
		parameters.add(OAuth2ParameterNames.ASSERTION, jwtBearerGrantRequest.getJwt().getTokenValue());
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

}
