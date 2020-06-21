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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.auth.ClientSecretJWT;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import java.net.URI;
import java.net.URISyntaxException;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

import java.util.Collections;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;

import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED_VALUE;

/**
 * Utility methods used by the {@link Converter}'s that convert
 * from an implementation of an {@link AbstractOAuth2AuthorizationGrantRequest}
 * to a {@link RequestEntity} representation of an OAuth 2.0 Access Token Request
 * for the specific Authorization Grant.
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

	/*
		Adding support for client assertion authentication
		https://tools.ietf.org/html/rfc7521#section-6.1
	 */

	static JWT getClientSecretAssertion(ClientRegistration clientRegistration){

		JWT clientAssertion = null;

		if (ClientAuthenticationMethod.SECRET_JWT.equals(clientRegistration.getClientAuthenticationMethod())) {

			try {
				ClientID clientID = new ClientID(clientRegistration.getClientId());
				URI audience = new URI(clientRegistration.getProviderDetails().getTokenUri());
				Secret secret = new Secret(clientRegistration.getClientSecret());
				JWSAlgorithm jwsAlgorithm = new JWSAlgorithm(clientRegistration.getClientAssertionSigningAlgorithm());

				//Generate a client secret JWT using nimbus libraries.
				clientAssertion = new ClientSecretJWT(clientID,
						audience
						, jwsAlgorithm
						, secret).getClientAssertion();
			} catch (JOSEException e) {
				OAuth2Error oauth2Error = new OAuth2Error("Client_secret_jwt",
						"Encountered an error generating a client secret JWT", null);
				throw new OAuth2AuthenticationException(oauth2Error, e.getMessage());

			} catch(URISyntaxException e){
				OAuth2Error oauth2Error = new OAuth2Error("token_endpoint",
						"The token endpoint provided or configured doesn't conform to a standard URI Pattern", null);
				throw new OAuth2AuthenticationException(oauth2Error, e.getMessage());
			}
		}

		return clientAssertion;
	}
}
