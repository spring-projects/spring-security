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

package org.springframework.security.oauth2.client.web.reactive.function.client.support;

import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.client.ClientRegistrationIdProcessor;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServerOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.support.WebClientHttpServiceGroupConfigurer;
import org.springframework.web.service.invoker.HttpRequestValues;

/**
 * Simplify adding OAuth2 support to interface based rest clients that use
 * {@link WebClient}.
 *
 * @author Rob Winch
 * @since 7.0
 */
public final class OAuth2WebClientHttpServiceGroupConfigurer implements WebClientHttpServiceGroupConfigurer {

	private final HttpRequestValues.Processor processor = ClientRegistrationIdProcessor.DEFAULT_INSTANCE;

	private final ExchangeFilterFunction filter;

	private OAuth2WebClientHttpServiceGroupConfigurer(ExchangeFilterFunction filter) {
		this.filter = filter;
	}

	@Override
	public void configureGroups(Groups<WebClient.Builder> groups) {
		// @formatter:off
		groups.forEachClient((group, client) ->
			client.filter(this.filter)
		);
		groups.forEachProxyFactory((group, factory) ->
			factory.httpRequestValuesProcessor(this.processor)
		);
		// @formatter:on
	}

	/**
	 * Create an instance for Reactive web applications from the provided
	 * {@link ReactiveOAuth2AuthorizedClientManager}.
	 *
	 * It will add {@link ServerOAuth2AuthorizedClientExchangeFilterFunction} to the
	 * {@link WebClient} and {@link ClientRegistrationIdProcessor} to the
	 * {@link org.springframework.web.service.invoker.HttpServiceProxyFactory}.
	 * @param authorizedClientManager the manager to use.
	 * @return the {@link OAuth2WebClientHttpServiceGroupConfigurer}.
	 */
	public static OAuth2WebClientHttpServiceGroupConfigurer from(
			ReactiveOAuth2AuthorizedClientManager authorizedClientManager) {
		ServerOAuth2AuthorizedClientExchangeFilterFunction filter = new ServerOAuth2AuthorizedClientExchangeFilterFunction(
				authorizedClientManager);
		return new OAuth2WebClientHttpServiceGroupConfigurer(filter);
	}

	/**
	 * Create an instance for Servlet based environments from the provided
	 * {@link OAuth2AuthorizedClientManager}.
	 *
	 * It will add {@link ServletOAuth2AuthorizedClientExchangeFilterFunction} to the
	 * {@link WebClient} and {@link ClientRegistrationIdProcessor} to the
	 * {@link org.springframework.web.service.invoker.HttpServiceProxyFactory}.
	 * @param authorizedClientManager the manager to use.
	 * @return the {@link OAuth2WebClientHttpServiceGroupConfigurer}.
	 */
	public static OAuth2WebClientHttpServiceGroupConfigurer from(
			OAuth2AuthorizedClientManager authorizedClientManager) {
		ServletOAuth2AuthorizedClientExchangeFilterFunction filter = new ServletOAuth2AuthorizedClientExchangeFilterFunction(
				authorizedClientManager);
		return new OAuth2WebClientHttpServiceGroupConfigurer(filter);
	}

}
