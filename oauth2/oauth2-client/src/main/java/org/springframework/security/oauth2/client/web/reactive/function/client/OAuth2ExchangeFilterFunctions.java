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

package org.springframework.security.oauth2.client.web.reactive.function.client;

import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.function.Consumer;

/**
 * @author Rob Winch
 * @since 5.1
 */
public final class OAuth2ExchangeFilterFunctions {

	/**
	 * Configures the WebClient for OAuth2 support in a servlet environment.
	 * @param repository the repository to use
	 * @return the {@link Consumer} to configure the WebClient
	 */
	public static Consumer<WebClient.Builder> oauth2ServletConfig(OAuth2AuthorizedClientRepository repository) {
		return new ServletOAuth2AuthorizedClientExchangeFilterFunction(repository)
				.oauth2Configuration();
	}

	/**
	 * Configures the WebClient for OAuth2 support in a servlet environment.
	 * @return the {@link Consumer} to configure the WebClient
	 */
	public static Consumer<WebClient.Builder> oauth2ServletConfig() {
		return new ServletOAuth2AuthorizedClientExchangeFilterFunction()
				.oauth2Configuration();
	}

	private OAuth2ExchangeFilterFunctions() {}
}
