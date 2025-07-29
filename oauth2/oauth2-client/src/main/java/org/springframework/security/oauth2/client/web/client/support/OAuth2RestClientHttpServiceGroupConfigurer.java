/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.oauth2.client.web.client.support;

import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.client.ClientRegistrationIdProcessor;
import org.springframework.security.oauth2.client.web.client.OAuth2ClientHttpRequestInterceptor;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.support.RestClientHttpServiceGroupConfigurer;
import org.springframework.web.service.invoker.HttpRequestValues;

/**
 * Simplify adding OAuth2 support to interface based rest clients that use
 * {@link RestClient}.
 *
 * It will add {@link OAuth2ClientHttpRequestInterceptor} to the {@link RestClient} and
 * {@link ClientRegistrationIdProcessor} to the
 * {@link org.springframework.web.service.invoker.HttpServiceProxyFactory}.
 *
 * @author Rob Winch
 * @since 7.0
 */
public final class OAuth2RestClientHttpServiceGroupConfigurer implements RestClientHttpServiceGroupConfigurer {

	private final HttpRequestValues.Processor processor = ClientRegistrationIdProcessor.DEFAULT_INSTANCE;

	private final ClientHttpRequestInterceptor interceptor;

	private OAuth2RestClientHttpServiceGroupConfigurer(ClientHttpRequestInterceptor interceptor) {
		this.interceptor = interceptor;
	}

	@Override
	public void configureGroups(Groups<RestClient.Builder> groups) {
		// @formatter:off
		groups.forEachClient((group, client) ->
			client.requestInterceptor(this.interceptor)
		);
		groups.forEachProxyFactory((group, factory) ->
			factory.httpRequestValuesProcessor(this.processor)
		);
		// @formatter:on
	}

	public static OAuth2RestClientHttpServiceGroupConfigurer from(
			OAuth2AuthorizedClientManager authorizedClientManager) {
		OAuth2ClientHttpRequestInterceptor interceptor = new OAuth2ClientHttpRequestInterceptor(
				authorizedClientManager);
		return new OAuth2RestClientHttpServiceGroupConfigurer(interceptor);
	}

}
