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

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * An implementation of an {@link OAuth2UserService} that supports custom {@link OAuth2User} types.
 * <p>
 * The custom user type(s) is supplied via the constructor,
 * using a {@code Map} of {@link OAuth2User} type(s) keyed by {@code String},
 * which represents the {@link ClientRegistration#getRegistrationId() Registration Id} of the Client.
 *
 * @author Joe Grandja
 * @see OAuth2UserService
 * @see OAuth2UserRequest
 * @see OAuth2User
 * @see ClientRegistration
 * @since 5.0
 */
public class CustomUserTypesOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

	private final Map<String, Class<? extends OAuth2User>> customUserTypes;
	private final RestTemplate restTemplate;
	private final ObjectMapper objectMapper;

	/**
	 * Constructs a {@code CustomUserTypesOAuth2UserService} using the provided parameters.
	 *
	 * @param customUserTypes a {@code Map} of {@link OAuth2User} type(s) keyed by {@link ClientRegistration#getRegistrationId() Registration Id}
	 */
	public CustomUserTypesOAuth2UserService(Map<String, Class<? extends OAuth2User>> customUserTypes) {
		this(customUserTypes, new RestTemplate(), null);
	}

	/**
	 * Constructs a {@code CustomUserTypesOAuth2UserService} using the provided parameters.
	 * @param customUserTypes a {@code Map} of {@link OAuth2User} type(s) keyed by {@link ClientRegistration#getRegistrationId() Registration Id}
	 * @param restTemplate
	 * @param objectMapper
	 */
	public CustomUserTypesOAuth2UserService(Map<String, Class<? extends OAuth2User>> customUserTypes, RestTemplate restTemplate, ObjectMapper objectMapper) {
		Assert.notEmpty(customUserTypes, "customUserTypes cannot be empty");
		this.customUserTypes = Collections.unmodifiableMap(new LinkedHashMap<>(customUserTypes));
		this.restTemplate = restTemplate;
		this.objectMapper = objectMapper;
	}

	@Override
	public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
		Assert.notNull(userRequest, "userRequest cannot be null");
		ClientRegistration clientRegistration = userRequest.getClientRegistration();
		String registrationId = clientRegistration.getRegistrationId();
		Class<? extends OAuth2User> customUserType;
		if ((customUserType = this.customUserTypes.get(registrationId)) == null) {
			return null;
		}
		String userInfoUri = clientRegistration.getProviderDetails().getUserInfoEndpoint().getUri();
		Map<String, Object> parameters = userRequest.getAdditionalParameters();
		if (StringUtils.isEmpty(userInfoUri) && objectMapper != null) {
			return objectMapper.convertValue(parameters, customUserType);
		}
		if (restTemplate != null) {
			String url = UriComponentsBuilder.fromHttpUrl(userInfoUri)
					.queryParam(OAuth2ParameterNames.ACCESS_TOKEN, userRequest.getAccessToken().getTokenValue())
					.buildAndExpand(parameters).toString();
			return restTemplate.getForObject(url, customUserType);
		}
		return null;
	}
}
