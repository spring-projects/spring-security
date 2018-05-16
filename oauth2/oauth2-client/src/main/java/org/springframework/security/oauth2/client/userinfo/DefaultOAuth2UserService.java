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

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RequestCallback;
import org.springframework.web.client.ResponseExtractor;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.util.*;

/**
 * An implementation of an {@link OAuth2UserService} that supports standard OAuth 2.0 Provider's.
 * <p>
 * For standard OAuth 2.0 Provider's, the attribute name used to access the user's name
 * from the UserInfo response is required and therefore must be available via
 * {@link org.springframework.security.oauth2.client.registration.ClientRegistration.ProviderDetails.UserInfoEndpoint#getUserNameAttributeName() UserInfoEndpoint.getUserNameAttributeName()}.
 *
 * <b>NOTE:</b> Attribute names are <b>not</b> standardized between providers and therefore will vary.
 * Please consult the provider's API documentation for the set of supported user attribute names.
 *
 * @author Joe Grandja
 * @see OAuth2UserService
 * @see OAuth2UserRequest
 * @see OAuth2User
 * @see DefaultOAuth2User
 * @since 5.0
 */
public class DefaultOAuth2UserService<T extends OAuth2UserRequest, R extends OAuth2User> implements OAuth2UserService<T, R>, ApplicationContextAware {
	private static final String MISSING_USER_NAME_ATTRIBUTE_ERROR_CODE = "missing_user_name_attribute";
	private static final String CANNOT_EXTRACT_USER_INFO_ERROR_CODE = "cannot_extract_user_info";
	private static final String OAUTH2_RESTTEMPLATE_BEAN_NAME = "oauth2RestTemplate";
	private static final String OAUTH2_OBJECTMAPPER_BEAN_NAME = "oauth2ObjectMapper";
	private final Map<String, RequestCallbackBuilder<T>> requestCallbackBuilders = new HashMap<>();
	private final Map<String, OAuth2UserExtractor<T, R>> extractors = new HashMap<>();
	private final RequestCallbackBuilder<T> defaultRequestCallback = new DefaultRequestCallbackBuilder();
	private OAuth2UserExtractor<T, R> defaultExtractor;
	private RestTemplate restTemplate;

	public DefaultOAuth2UserService() {
		addRequestCallbackBuilder(OAuth2ParameterNames.USER_INFO_DEFAULT, defaultRequestCallback);
	}

	@Override
	public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
		this.restTemplate = applicationContext.containsBean(OAUTH2_RESTTEMPLATE_BEAN_NAME) ?
				applicationContext.getBean(OAUTH2_RESTTEMPLATE_BEAN_NAME, RestTemplate.class) :
				new RestTemplate();
		ObjectMapper objectMapper = applicationContext.containsBean(OAUTH2_OBJECTMAPPER_BEAN_NAME) ?
				applicationContext.getBean(OAUTH2_OBJECTMAPPER_BEAN_NAME, ObjectMapper.class) :
				Jackson2ObjectMapperBuilder.json().build();
		this.defaultExtractor = new DefaultOAuth2UserExtractor(objectMapper);
		addExtractor(OAuth2ParameterNames.JSON_EXTRACTOR, defaultExtractor);
		BeanFactoryUtils.
				beansOfTypeIncludingAncestors(applicationContext, RequestCallbackBuilder.class)
				.forEach(this::addRequestCallbackBuilder);
		BeanFactoryUtils.
				beansOfTypeIncludingAncestors(applicationContext, OAuth2UserExtractor.class)
				.forEach(this::addExtractor);
	}

	public DefaultOAuth2UserService addRequestCallbackBuilder(String name, RequestCallbackBuilder<T> builder) {
		requestCallbackBuilders.put(name, builder);
		return this;
	}

	public DefaultOAuth2UserService addExtractor(String name, OAuth2UserExtractor<T, R> extractor) {
		extractors.put(name, extractor);
		return this;
	}

	@Override
	public R loadUser(T userRequest) throws OAuth2AuthenticationException {
		Assert.notNull(userRequest, "userRequest cannot be null");
		ClientRegistration clientRegistration = userRequest.getClientRegistration();
		String userInfoUri = clientRegistration
				.getProviderDetails().getUserInfoEndpoint().getUri();
		ResponseExtractor<R> extractor = extractors.getOrDefault(clientRegistration
				.getProviderDetails().getUserInfoEndpoint().getExtractorName(), defaultExtractor)
				.apply(userRequest);
		if (StringUtils.isEmpty(userInfoUri)) {
			try {
				return extractor.extractData(null);
			} catch (IOException e) {
				OAuth2Error oauth2Error = new OAuth2Error(
						CANNOT_EXTRACT_USER_INFO_ERROR_CODE,
						"Cannot extract user info in UserInfoEndpoint for Client Registration: " +
								userRequest.getClientRegistration().getRegistrationId(),
						null
				);
				throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
			}
		}
		String url = UriComponentsBuilder.fromHttpUrl(userInfoUri)
				.queryParam(OAuth2ParameterNames.ACCESS_TOKEN, userRequest.getAccessToken().getTokenValue())
				.buildAndExpand(userRequest.getAdditionalParameters()).toString();
		RequestCallback requestCallback = requestCallbackBuilders.getOrDefault(clientRegistration
				.getProviderDetails().getUserInfoEndpoint().getRequestName(), defaultRequestCallback)
				.apply(userRequest);
		return restTemplate.execute(url, clientRegistration
				.getProviderDetails().getUserInfoEndpoint().getMethod(), requestCallback, extractor);
	}

	public interface RequestCallbackBuilder<T extends OAuth2UserRequest> {
		RequestCallback apply(T userRequest);
	}

	public interface OAuth2UserExtractor<T extends OAuth2UserRequest, R extends OAuth2User> {
		ResponseExtractor<R> apply(T userRequest);
	}

	public class DefaultRequestCallbackBuilder implements RequestCallbackBuilder<T> {
		@Override
		public RequestCallback apply(T userRequest) {
			return clientHttpRequest ->
					clientHttpRequest.getHeaders().setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
		}
	}

	public class DefaultOAuth2UserExtractor implements OAuth2UserExtractor<T, R> {

		private final ObjectMapper objectMapper;
		private final TypeReference<Map<String, Object>> typeReference = new TypeReference<Map<String, Object>>() {
		};

		public DefaultOAuth2UserExtractor(ObjectMapper objectMapper) {
			this.objectMapper = objectMapper;
		}

		@Override
		public ResponseExtractor<OAuth2User> apply(OAuth2UserRequest userRequest) {
			return response -> {
				ClientRegistration clientRegistration = userRequest.getClientRegistration();
				String userNameAttributeName = clientRegistration.getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName();
				if (!StringUtils.hasText(userNameAttributeName)) {
					OAuth2Error oauth2Error = new OAuth2Error(
							MISSING_USER_NAME_ATTRIBUTE_ERROR_CODE,
							"Missing required \"user name\" attribute name in UserInfoEndpoint for Client Registration: " +
									userRequest.getClientRegistration().getRegistrationId(),
							null
					);
					throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
				}
				Map<String, Object> userAttributes = objectMapper.readValue(response.getBody(), typeReference);
				GrantedAuthority authority = new OAuth2UserAuthority(userAttributes);
				Set<GrantedAuthority> authorities = new HashSet<>();
				authorities.add(authority);
				return new DefaultOAuth2User(authorities, userAttributes, userNameAttributeName);
			};
		}
	}

}
