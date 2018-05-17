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

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.util.Assert;
import org.springframework.web.client.ResponseExtractor;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Created by XYUU <xyuu@xyuu.net> on 2018/5/16.
 */
public class CustomOAuth2UserExtractor implements DefaultOAuth2UserService.OAuth2UserExtractor<OAuth2UserRequest, OAuth2User>,
		ApplicationContextAware {
	public static final String NAME = "custom";
	private static final String OAUTH2_OBJECTMAPPER_BEAN_NAME = "oauth2ObjectMapper";
	private final Map<String, Class<? extends OAuth2User>> customUserTypes;
	private ObjectMapper objectMapper;

	public CustomOAuth2UserExtractor(Map<String, Class<? extends OAuth2User>> customUserTypes) {
		Assert.notEmpty(customUserTypes, "customUserTypes cannot be empty");
		this.customUserTypes = Collections.unmodifiableMap(new LinkedHashMap<>(customUserTypes));
	}

	@Override
	public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
		this.objectMapper = applicationContext.containsBean(OAUTH2_OBJECTMAPPER_BEAN_NAME) ?
				applicationContext.getBean(OAUTH2_OBJECTMAPPER_BEAN_NAME, ObjectMapper.class) :
				Jackson2ObjectMapperBuilder.json().build();
	}

	@Override
	public ResponseExtractor<OAuth2User> apply(OAuth2UserRequest userRequest) {
		String registrationId = userRequest.getClientRegistration().getRegistrationId();
		Class<? extends OAuth2User> customUserType;
		if ((customUserType = this.customUserTypes.get(registrationId)) == null) {
			return null;
		}
		return response -> objectMapper.readValue(response.getBody(), customUserType);
	}

}
