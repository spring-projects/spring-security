/*
 * Copyright 2002-2020 the original author or authors.
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

package org.springframework.security.oauth2.client.userinfo;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.core.convert.converter.Converter;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.util.Assert;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

/**
 * An implementation of an {@link OAuth2UserService} that supports custom
 * {@link OAuth2User} types.
 * <p>
 * The custom user type(s) is supplied via the constructor, using a {@code Map} of
 * {@link OAuth2User} type(s) keyed by {@code String}, which represents the
 * {@link ClientRegistration#getRegistrationId() Registration Id} of the Client.
 *
 * @deprecated It is recommended to use a delegation-based strategy of an
 * {@link OAuth2UserService} to support custom {@link OAuth2User} types, as it provides
 * much greater flexibility compared to this implementation. See the
 * <a target="_blank" href=
 * "https://docs.spring.io/spring-security/site/docs/current/reference/html5/#oauth2login-advanced-map-authorities-oauth2userservice">reference
 * manual</a> for details on how to implement.
 * @author Joe Grandja
 * @since 5.0
 * @see OAuth2UserService
 * @see OAuth2UserRequest
 * @see OAuth2User
 * @see ClientRegistration
 */
@Deprecated
public class CustomUserTypesOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

	private static final String INVALID_USER_INFO_RESPONSE_ERROR_CODE = "invalid_user_info_response";

	private final Map<String, Class<? extends OAuth2User>> customUserTypes;

	private Converter<OAuth2UserRequest, RequestEntity<?>> requestEntityConverter = new OAuth2UserRequestEntityConverter();

	private RestOperations restOperations;

	/**
	 * Constructs a {@code CustomUserTypesOAuth2UserService} using the provided
	 * parameters.
	 * @param customUserTypes a {@code Map} of {@link OAuth2User} type(s) keyed by
	 * {@link ClientRegistration#getRegistrationId() Registration Id}
	 */
	public CustomUserTypesOAuth2UserService(Map<String, Class<? extends OAuth2User>> customUserTypes) {
		Assert.notEmpty(customUserTypes, "customUserTypes cannot be empty");
		this.customUserTypes = Collections.unmodifiableMap(new LinkedHashMap<>(customUserTypes));
		RestTemplate restTemplate = new RestTemplate();
		restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
		this.restOperations = restTemplate;
	}

	@Override
	public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
		Assert.notNull(userRequest, "userRequest cannot be null");
		String registrationId = userRequest.getClientRegistration().getRegistrationId();
		Class<? extends OAuth2User> customUserType = this.customUserTypes.get(registrationId);
		if (customUserType == null) {
			return null;
		}

		RequestEntity<?> request = this.requestEntityConverter.convert(userRequest);

		ResponseEntity<? extends OAuth2User> response;
		try {
			response = this.restOperations.exchange(request, customUserType);
		}
		catch (RestClientException ex) {
			OAuth2Error oauth2Error = new OAuth2Error(INVALID_USER_INFO_RESPONSE_ERROR_CODE,
					"An error occurred while attempting to retrieve the UserInfo Resource: " + ex.getMessage(), null);
			throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString(), ex);
		}

		OAuth2User oauth2User = response.getBody();

		return oauth2User;
	}

	/**
	 * Sets the {@link Converter} used for converting the {@link OAuth2UserRequest} to a
	 * {@link RequestEntity} representation of the UserInfo Request.
	 * @param requestEntityConverter the {@link Converter} used for converting to a
	 * {@link RequestEntity} representation of the UserInfo Request
	 * @since 5.1
	 */
	public final void setRequestEntityConverter(Converter<OAuth2UserRequest, RequestEntity<?>> requestEntityConverter) {
		Assert.notNull(requestEntityConverter, "requestEntityConverter cannot be null");
		this.requestEntityConverter = requestEntityConverter;
	}

	/**
	 * Sets the {@link RestOperations} used when requesting the UserInfo resource.
	 *
	 * <p>
	 * <b>NOTE:</b> At a minimum, the supplied {@code restOperations} must be configured
	 * with the following:
	 * <ol>
	 * <li>{@link ResponseErrorHandler} - {@link OAuth2ErrorResponseErrorHandler}</li>
	 * </ol>
	 * @param restOperations the {@link RestOperations} used when requesting the UserInfo
	 * resource
	 * @since 5.1
	 */
	public final void setRestOperations(RestOperations restOperations) {
		Assert.notNull(restOperations, "restOperations cannot be null");
		this.restOperations = restOperations;
	}

}
