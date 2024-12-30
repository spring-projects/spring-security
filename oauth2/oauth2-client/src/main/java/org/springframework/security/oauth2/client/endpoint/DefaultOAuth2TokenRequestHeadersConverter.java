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

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;

import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

/**
 * Default {@link Converter} used to convert an
 * {@link AbstractOAuth2AuthorizationGrantRequest} to the {@link HttpHeaders} of a
 * {@link RequestEntity} representation of an OAuth 2.0 Access Token Request for the
 * specific Authorization Grant.
 *
 * @author Peter Eastham
 * @author Steve Riesenberg
 * @since 6.3
 * @see AbstractOAuth2AuthorizationGrantRequestEntityConverter
 */
public final class DefaultOAuth2TokenRequestHeadersConverter<T extends AbstractOAuth2AuthorizationGrantRequest>
		implements Converter<T, HttpHeaders> {

	private static final MediaType APPLICATION_JSON_UTF8 = new MediaType(MediaType.APPLICATION_JSON,
			StandardCharsets.UTF_8);

	private static final MediaType APPLICATION_FORM_URLENCODED_UTF8 = new MediaType(
			MediaType.APPLICATION_FORM_URLENCODED, StandardCharsets.UTF_8);

	private List<MediaType> accept = List.of(MediaType.APPLICATION_JSON);

	private MediaType contentType = MediaType.APPLICATION_FORM_URLENCODED;

	private boolean encodeClientCredentials = true;

	/**
	 * Populates the default headers for the token request.
	 * @param grantRequest the authorization grant request
	 * @return the headers populated for the token request
	 */
	@Override
	public HttpHeaders convert(T grantRequest) {
		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(this.accept);
		headers.setContentType(this.contentType);
		ClientRegistration clientRegistration = grantRequest.getClientRegistration();
		if (ClientAuthenticationMethod.CLIENT_SECRET_BASIC.equals(clientRegistration.getClientAuthenticationMethod())) {
			String clientId = encodeClientCredentialIfRequired(clientRegistration.getClientId());
			String clientSecret = encodeClientCredentialIfRequired(clientRegistration.getClientSecret());
			headers.setBasicAuth(clientId, clientSecret);
		}
		return headers;
	}

	private String encodeClientCredentialIfRequired(String clientCredential) {
		if (!this.encodeClientCredentials) {
			return clientCredential;
		}
		return URLEncoder.encode(clientCredential, StandardCharsets.UTF_8);
	}

	/**
	 * Sets whether the client credentials of the {@code Authorization} header will be
	 * encoded using the {@code application/x-www-form-urlencoded} encoding algorithm
	 * according to RFC 6749. Default is {@code true}.
	 * @param encodeClientCredentials whether the client credentials will be encoded
	 * @see <a target="_blank" href=
	 * "https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.1">2.3.1 Client
	 * Password</a>
	 */
	public void setEncodeClientCredentials(boolean encodeClientCredentials) {
		this.encodeClientCredentials = encodeClientCredentials;
	}

	/**
	 * Creates a {@link DefaultOAuth2TokenRequestHeadersConverter} that populates default
	 * {@link HttpHeaders} that includes {@code charset=UTF-8} on both the {@code Accept}
	 * and {@code Content-Type} headers to provide backwards compatibility for
	 * {@link AbstractOAuth2AuthorizationGrantRequestEntityConverter}.
	 * @return the default headers converter
	 */
	static <T extends AbstractOAuth2AuthorizationGrantRequest> DefaultOAuth2TokenRequestHeadersConverter<T> withCharsetUtf8() {
		DefaultOAuth2TokenRequestHeadersConverter<T> converter = new DefaultOAuth2TokenRequestHeadersConverter<>();
		converter.accept = List.of(APPLICATION_JSON_UTF8);
		converter.contentType = APPLICATION_FORM_URLENCODED_UTF8;
		return converter;
	}

}
