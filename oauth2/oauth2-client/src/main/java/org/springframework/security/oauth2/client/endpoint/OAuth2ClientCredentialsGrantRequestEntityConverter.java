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
import org.springframework.http.HttpMethod;
import org.springframework.http.RequestEntity;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.CollectionUtils;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;

/**
 * A {@link Converter} that converts the provided
 * {@link OAuth2ClientCredentialsGrantRequest} to a {@link RequestEntity} representation
 * of an OAuth 2.0 Access Token Request for the Client Credentials Grant.
 *
 * @author Joe Grandja
 * @since 5.1
 * @see Converter
 * @see OAuth2ClientCredentialsGrantRequest
 * @see RequestEntity
 */
public class OAuth2ClientCredentialsGrantRequestEntityConverter
		implements Converter<OAuth2ClientCredentialsGrantRequest, RequestEntity<?>> {

	/**
	 * Returns the {@link RequestEntity} used for the Access Token Request.
	 * @param clientCredentialsGrantRequest the client credentials grant request
	 * @return the {@link RequestEntity} used for the Access Token Request
	 */
	@Override
	public RequestEntity<?> convert(OAuth2ClientCredentialsGrantRequest clientCredentialsGrantRequest) {
		ClientRegistration clientRegistration = clientCredentialsGrantRequest.getClientRegistration();

		HttpHeaders headers = OAuth2AuthorizationGrantRequestEntityUtils.getTokenRequestHeaders(clientRegistration);
		MultiValueMap<String, String> formParameters = this.buildFormParameters(clientCredentialsGrantRequest);
		URI uri = UriComponentsBuilder.fromUriString(clientRegistration.getProviderDetails().getTokenUri()).build()
				.toUri();

		return new RequestEntity<>(formParameters, headers, HttpMethod.POST, uri);
	}

	/**
	 * Returns a {@link MultiValueMap} of the form parameters used for the Access Token
	 * Request body.
	 * @param clientCredentialsGrantRequest the client credentials grant request
	 * @return a {@link MultiValueMap} of the form parameters used for the Access Token
	 * Request body
	 */
	private MultiValueMap<String, String> buildFormParameters(
			OAuth2ClientCredentialsGrantRequest clientCredentialsGrantRequest) {
		ClientRegistration clientRegistration = clientCredentialsGrantRequest.getClientRegistration();

		MultiValueMap<String, String> formParameters = new LinkedMultiValueMap<>();
		formParameters.add(OAuth2ParameterNames.GRANT_TYPE, clientCredentialsGrantRequest.getGrantType().getValue());
		if (!CollectionUtils.isEmpty(clientRegistration.getScopes())) {
			formParameters.add(OAuth2ParameterNames.SCOPE,
					StringUtils.collectionToDelimitedString(clientRegistration.getScopes(), " "));
		}
		if (ClientAuthenticationMethod.POST.equals(clientRegistration.getClientAuthenticationMethod())) {
			formParameters.add(OAuth2ParameterNames.CLIENT_ID, clientRegistration.getClientId());
			formParameters.add(OAuth2ParameterNames.CLIENT_SECRET, clientRegistration.getClientSecret());
		}

		return formParameters;
	}

}
