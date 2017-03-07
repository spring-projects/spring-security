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
package org.springframework.security.oauth2.client.authorization;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2Attributes;
import org.springframework.security.oauth2.core.ResponseType;
import org.springframework.security.oauth2.core.protocol.AuthorizationRequestAttributes;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.stream.Collectors;

/**
 * @author Joe Grandja
 */
public class DefaultAuthorizationRequestUriBuilder implements AuthorizationRequestUriBuilder {

	@Override
	public URI build(AuthorizationRequestAttributes authorizationRequestAttributes) throws URISyntaxException {
		UriComponentsBuilder uriBuilder = UriComponentsBuilder
				.fromUri(authorizationRequestAttributes.getAuthorizeUri());

		if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(authorizationRequestAttributes.getGrantType())) {
			uriBuilder.queryParam(OAuth2Attributes.RESPONSE_TYPE, ResponseType.CODE.value());
			if (authorizationRequestAttributes.getRedirectUri() != null) {
				uriBuilder.queryParam(OAuth2Attributes.REDIRECT_URI, authorizationRequestAttributes.getRedirectUri());
			}
		} else if (AuthorizationGrantType.IMPLICIT.equals(authorizationRequestAttributes.getGrantType())) {
			uriBuilder
					.queryParam(OAuth2Attributes.RESPONSE_TYPE, ResponseType.TOKEN.value())
					.queryParam(OAuth2Attributes.REDIRECT_URI, authorizationRequestAttributes.getRedirectUri());
		}

		uriBuilder
				.queryParam(OAuth2Attributes.CLIENT_ID, authorizationRequestAttributes.getClientId())
				.queryParam(OAuth2Attributes.SCOPE,
						authorizationRequestAttributes.getScopes().stream().collect(Collectors.joining(" ")))
				.queryParam(OAuth2Attributes.STATE, authorizationRequestAttributes.getState());

		return uriBuilder.build().encode().toUri();
	}
}