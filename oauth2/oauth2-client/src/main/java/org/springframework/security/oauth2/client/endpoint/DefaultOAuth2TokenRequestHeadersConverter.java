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

import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Collections;

/**
 * Default {@link Converter} used to convert an
 * {@link AbstractOAuth2AuthorizationGrantRequest} to the {@link HttpHeaders} of aKk
 * {@link RequestEntity} representation of an OAuth 2.0 Access Token Request for the
 * specific Authorization Grant.
 *
 * @author Peter Eastham
 * @author Joe Grandja
 * @see AbstractOAuth2AuthorizationGrantRequestEntityConverter
 * @since 6.3
 */
public final class DefaultOAuth2TokenRequestHeadersConverter<T extends AbstractOAuth2AuthorizationGrantRequest>
		implements Converter<T, HttpHeaders> {

	private MediaType accept = MediaType.APPLICATION_JSON;

	private MediaType contentType = MediaType.APPLICATION_FORM_URLENCODED;

	private boolean encodeClientCredentialsIfRequired = true;

	/**
	 * Populates the headers for the token request.
	 * @param grantRequest the grant request
	 * @return the headers populated for the token request
	 */
	@Override
	public HttpHeaders convert(T grantRequest) {
		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Collections.singletonList(accept));
		headers.setContentType(contentType);
		ClientRegistration clientRegistration = grantRequest.getClientRegistration();
		if (ClientAuthenticationMethod.CLIENT_SECRET_BASIC.equals(clientRegistration.getClientAuthenticationMethod())) {
			String clientId = encodeClientCredential(clientRegistration.getClientId());
			String clientSecret = encodeClientCredential(clientRegistration.getClientSecret());
			headers.setBasicAuth(clientId, clientSecret);
		}
		return headers;
	}

	private String encodeClientCredential(String clientCredential) {
		String encodedCredential = clientCredential;
		if (this.encodeClientCredentialsIfRequired) {
			encodedCredential = URLEncoder.encode(clientCredential, StandardCharsets.UTF_8);
		}
		return encodedCredential;
	}

	/**
	 * Sets the behavior for if this URL Encoding the Client Credentials during the
	 * conversion.
	 * @param encodeClientCredentialsIfRequired if false, no URL encoding will happen
	 */
	public void setEncodeClientCredentials(boolean encodeClientCredentialsIfRequired) {
		this.encodeClientCredentialsIfRequired = encodeClientCredentialsIfRequired;
	}

	/**
	 * MediaType to set for the Accept header. Default is application/json
	 * @param accept MediaType to use for the Accept header
	 */
	private void setAccept(MediaType accept) {
		this.accept = accept;
	}

	/**
	 * MediaType to set for the Content Type header. Default is
	 * application/x-www-form-urlencoded
	 * @param contentType MediaType to use for the Content Type header
	 */
	private void setContentType(MediaType contentType) {
		this.contentType = contentType;
	}

	static <T extends AbstractOAuth2AuthorizationGrantRequest> DefaultOAuth2TokenRequestHeadersConverter<T> historicalConverter() {
		DefaultOAuth2TokenRequestHeadersConverter<T> converter = new DefaultOAuth2TokenRequestHeadersConverter<>();
		converter.setAccept(MediaType.APPLICATION_JSON_UTF8);
		converter.setContentType(MediaType.valueOf(MediaType.APPLICATION_FORM_URLENCODED_VALUE + ";charset=UTF-8"));
		return converter;
	}

}
