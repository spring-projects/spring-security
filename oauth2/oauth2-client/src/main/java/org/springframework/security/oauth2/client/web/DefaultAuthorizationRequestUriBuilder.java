/*
 * Copyright 2002-2017 the original author or authors.
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
package org.springframework.security.oauth2.client.web;

import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.Assert;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import java.util.Set;

/**
 * A {@code MultiValueMap<String, String>} builder for an OAuth 2.0 Authorization Request Params.
 *
 * @author XYUU
 * @see OAuth2AuthorizationRequest
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1.1">Section 4.1.1 Authorization Code Grant Request</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.2.1">Section 4.2.1 Implicit Grant Request</a>
 * @since 5.0
 */
public class DefaultAuthorizationRequestUriParamsBuilder extends AbstractAuthorizationRequestUriBuilder {

	public static final String DEFAULT = "default";

	@Override
	public MultiValueMap<String, String> apply(OAuth2AuthorizationRequest authorizationRequest) {
		Assert.notNull(authorizationRequest, "authorizationRequest cannot be null");
		Set<String> scopes = authorizationRequest.getScopes();
		MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
		map.add(OAuth2ParameterNames.RESPONSE_TYPE, authorizationRequest.getResponseType().getValue());
		map.add(OAuth2ParameterNames.CLIENT_ID, authorizationRequest.getClientId());
		map.add(OAuth2ParameterNames.SCOPE, StringUtils.collectionToDelimitedString(scopes, " "));
		map.add(OAuth2ParameterNames.STATE, authorizationRequest.getState());
		if (authorizationRequest.getRedirectUri() != null) {
			map.add(OAuth2ParameterNames.REDIRECT_URI, authorizationRequest.getRedirectUri());
		}
		return map;
	}

}
