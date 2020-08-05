/*
 * Copyright 2002-2018 the original author or authors.
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

import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

import java.util.Collections;

import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED_VALUE;

/**
 * Utility methods used by the {@link Converter}'s that convert from an implementation of
 * an {@link AbstractOAuth2AuthorizationGrantRequest} to a {@link RequestEntity}
 * representation of an OAuth 2.0 Access Token Request for the specific Authorization
 * Grant.
 *
 * @author Joe Grandja
 * @since 5.1
 * @see OAuth2AuthorizationCodeGrantRequestEntityConverter
 * @see OAuth2ClientCredentialsGrantRequestEntityConverter
 */
final class OAuth2AuthorizationGrantRequestEntityUtils {

	private static HttpHeaders DEFAULT_TOKEN_REQUEST_HEADERS = getDefaultTokenRequestHeaders();

	static HttpHeaders getTokenRequestHeaders(ClientRegistration clientRegistration) {
		HttpHeaders headers = new HttpHeaders();
		headers.addAll(DEFAULT_TOKEN_REQUEST_HEADERS);
		if (ClientAuthenticationMethod.BASIC.equals(clientRegistration.getClientAuthenticationMethod())) {
			headers.setBasicAuth(clientRegistration.getClientId(), clientRegistration.getClientSecret());
		}
		return headers;
	}

	private static HttpHeaders getDefaultTokenRequestHeaders() {
		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON_UTF8));
		final MediaType contentType = MediaType.valueOf(APPLICATION_FORM_URLENCODED_VALUE + ";charset=UTF-8");
		headers.setContentType(contentType);
		return headers;
	}

}
