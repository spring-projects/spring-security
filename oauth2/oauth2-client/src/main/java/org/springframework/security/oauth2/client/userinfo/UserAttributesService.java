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
package org.springframework.security.oauth2.client.userinfo;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Map;

/**
 * Created by XYUU <xyuu@xyuu.net> on 2018/4/25.
 */
public abstract class UserAttributesService<T> extends ParameterizedTypeReference<T> {

	String INVALID_USER_INFO_RESPONSE_ERROR_CODE = "invalid_user_info_response";

	ParameterizedTypeReference<Map<String, Object>> typeReference = new ParameterizedTypeReference<Map<String, Object>>() {
	};

	MappingJackson2HttpMessageConverter jackson2HttpMessageConverter = new MappingJackson2HttpMessageConverter();

	public T getUserAttributes(ClientRegistration clientRegistration, OAuth2UserRequest userRequest) {
		String userInfoUri = clientRegistration.getProviderDetails().getUserInfoEndpoint().getUri();
		Map<String, Object> parameters = userRequest.getAdditionalParameters();
		Map<String, Object> userAttributes;
		if (!StringUtils.isEmpty(userInfoUri) && getRestTemplate() != null) {
			String url = UriComponentsBuilder.fromHttpUrl(userInfoUri)
					.queryParam(OAuth2ParameterNames.ACCESS_TOKEN, userRequest.getAccessToken().getTokenValue())
					.buildAndExpand(parameters).toString();
			T resp = getRestTemplate().execute(url, HttpMethod.GET,
					request -> request.getHeaders().setContentType(MediaType.APPLICATION_FORM_URLENCODED),
					response -> (T) jackson2HttpMessageConverter.read(getType(), null, response)
			);
			if (HttpStatus.OK.equals(resp.getStatusCode())) {
				userAttributes = resp.getBody();
			} else {
				OAuth2Error oauth2Error = new OAuth2Error(
						INVALID_USER_INFO_RESPONSE_ERROR_CODE,
						"An error occurred while sending the UserInfo Request for Client Registration: " +
								clientRegistration.getRegistrationId() +
								" Status Code:" + resp.getStatusCodeValue(),
						null
				);
				throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
			}
		} else {
			userAttributes = parameters;
		}
		return userAttributes;
	}

	protected abstract RestTemplate getRestTemplate();
}
