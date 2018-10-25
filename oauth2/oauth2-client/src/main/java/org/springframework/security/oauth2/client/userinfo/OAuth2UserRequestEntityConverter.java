/*
 * Copyright 2002-2018 the original author or authors.
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
package org.springframework.security.oauth2.client.userinfo;

import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.Collections;

import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED_VALUE;

/**
 * A {@link Converter} that converts the provided {@link OAuth2UserRequest}
 * to a {@link RequestEntity} representation of a request for the UserInfo Endpoint.
 *
 * @author Joe Grandja
 * @since 5.1
 * @see Converter
 * @see OAuth2UserRequest
 * @see RequestEntity
 */
public class OAuth2UserRequestEntityConverter implements Converter<OAuth2UserRequest, RequestEntity<?>> {
	private static final MediaType DEFAULT_CONTENT_TYPE = MediaType.valueOf(APPLICATION_FORM_URLENCODED_VALUE + ";charset=UTF-8");

	/**
	 * Returns the {@link RequestEntity} used for the UserInfo Request.
	 *
	 * @param userRequest the user request
	 * @return the {@link RequestEntity} used for the UserInfo Request
	 */
	@Override
	public RequestEntity<?> convert(OAuth2UserRequest userRequest) {
		ClientRegistration clientRegistration = userRequest.getClientRegistration();

		HttpMethod httpMethod = HttpMethod.GET;
		if (AuthenticationMethod.FORM.equals(clientRegistration.getProviderDetails().getUserInfoEndpoint().getAuthenticationMethod())) {
			httpMethod = HttpMethod.POST;
		}
		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
		URI uri = UriComponentsBuilder.fromUriString(clientRegistration.getProviderDetails().getUserInfoEndpoint().getUri())
				.build()
				.toUri();

		RequestEntity<?> request;
		if (HttpMethod.POST.equals(httpMethod)) {
			headers.setContentType(DEFAULT_CONTENT_TYPE);
			MultiValueMap<String, String> formParameters = new LinkedMultiValueMap<>();
			formParameters.add(OAuth2ParameterNames.ACCESS_TOKEN, userRequest.getAccessToken().getTokenValue());
			request = new RequestEntity<>(formParameters, headers, httpMethod, uri);
		} else {
			headers.setBearerAuth(userRequest.getAccessToken().getTokenValue());
			request = new RequestEntity<>(headers, httpMethod, uri);
		}

		return request;
	}
}
