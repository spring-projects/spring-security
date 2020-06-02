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
package org.springframework.security.oauth2.server.resource.introspection;

import org.springframework.http.client.support.BasicAuthenticationInterceptor;
import org.springframework.util.Assert;
import org.springframework.web.client.RestTemplate;

/**
 * Preconfigured and customizable {@link OpaqueTokenIntrospectorRestTemplateFactory}
 */
public class DefaultOpaqueTokenIntrospectorRestTemplateFactory implements OpaqueTokenIntrospectorRestTemplateFactory {
	public static final OpaqueTokenIntrospectorRestTemplateFactory DEFAULT = new DefaultOpaqueTokenIntrospectorRestTemplateFactory();

	private final Customizer customizer;

	public DefaultOpaqueTokenIntrospectorRestTemplateFactory() {
		this(null);
	}

	public DefaultOpaqueTokenIntrospectorRestTemplateFactory(Customizer customizer) {
		this.customizer = customizer;
	}

	@Override
	public RestTemplate create(String clientId, String clientSecret) {
		Assert.notNull(clientId, "clientId cannot be null");
		Assert.notNull(clientSecret, "clientSecret cannot be null");

		RestTemplate restTemplate = new RestTemplate();
		restTemplate.getInterceptors().add(new BasicAuthenticationInterceptor(clientId, clientSecret));
		if (customizer != null) {
			customizer.customize(restTemplate);
		}
		return restTemplate;
	}
}
