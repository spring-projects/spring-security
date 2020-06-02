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
package org.springframework.security.oauth2.client.endpoint;

import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.web.client.RestTemplate;

import java.util.Arrays;

/**
 * Factory for creating {@link RestTemplate} used by various OAuth2 classes.
 *
 * @since 5.3
 */
public class OAuth2RestTemplateFactory {
	public static final OAuth2RestTemplateFactory DEFAULT = new OAuth2RestTemplateFactory();

	private final Customizer customizer;

	public OAuth2RestTemplateFactory() {
		this(null);
	}

	public OAuth2RestTemplateFactory(Customizer customizer) {
		this.customizer = customizer;
	}

	/**
	 * Create OAuth2 {@link RestTemplate}
	 */
	public RestTemplate create() {
		RestTemplate restTemplate = new RestTemplate(Arrays.asList(
				new FormHttpMessageConverter(),
				new OAuth2AccessTokenResponseHttpMessageConverter()));
		restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
		if (customizer != null) {
			customizer.customize(restTemplate);
		}
		return restTemplate;

	}

	/**
	 * Callback interface that can be used to customize a {@link RestTemplate}.
	 *
	 * @since 5.3
	 */
	@FunctionalInterface
	interface Customizer {
		/**
		 * Callback to customize a {@link RestTemplate} instance.
		 *
		 * @param restTemplate the template to customize
		 */
		void customize(RestTemplate restTemplate);
	}
}
