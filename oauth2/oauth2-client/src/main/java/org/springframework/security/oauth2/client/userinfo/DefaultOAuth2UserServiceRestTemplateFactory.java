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

import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

/**
 * Preconfigured and customizable {@link OAuth2UserServiceRestTemplateFactory}
 */
public class DefaultOAuth2UserServiceRestTemplateFactory implements OAuth2UserServiceRestTemplateFactory {
	public static final DefaultOAuth2UserServiceRestTemplateFactory DEFAULT = new DefaultOAuth2UserServiceRestTemplateFactory();

	private final Customizer customizer;

	public DefaultOAuth2UserServiceRestTemplateFactory() {
		this(null);
	}

	public DefaultOAuth2UserServiceRestTemplateFactory(Customizer customizer) {
		this.customizer = customizer;
	}

	@Override
	public RestTemplate create() {
		RestTemplate restTemplate = new RestTemplate();
		restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
		if (customizer != null) {
			customizer.customize(restTemplate);
		}
		return restTemplate;
	}
}
