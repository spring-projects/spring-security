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

package org.springframework.security.oauth2.client.web;

import java.util.Map;
import java.util.function.Consumer;

import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.util.Assert;

/**
 * Used for accessing the attribute that stores the the
 * {@link ClientRegistration#getRegistrationId()}. This ensures that
 * {@link org.springframework.security.oauth2.client.web.client.ClientRegistrationIdProcessor}
 * aligns with all of ways of setting on both
 * {@link org.springframework.web.client.RestClient} and
 * {@link org.springframework.web.reactive.function.client.WebClient}.
 *
 * @see org.springframework.security.oauth2.client.web.client.ClientRegistrationIdProcessor
 * @see org.springframework.security.oauth2.client.web.client.RequestAttributeClientRegistrationIdResolver
 * @see org.springframework.security.oauth2.client.web.reactive.function.client.ServerOAuth2AuthorizedClientExchangeFilterFunction
 * @see org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction
 */
public final class ClientAttributes {

	private static final String CLIENT_REGISTRATION_ID_ATTR_NAME = ClientRegistration.class.getName()
		.concat(".CLIENT_REGISTRATION_ID");

	/**
	 * Resolves the {@link ClientRegistration#getRegistrationId() clientRegistrationId} to
	 * be used to look up the {@link OAuth2AuthorizedClient}.
	 * @param attributes the to search
	 * @return the registration id to use.
	 */
	public static String resolveClientRegistrationId(Map<String, Object> attributes) {
		return (String) attributes.get(CLIENT_REGISTRATION_ID_ATTR_NAME);
	}

	/**
	 * Produces a Consumer that adds the {@link ClientRegistration#getRegistrationId()
	 * clientRegistrationId} to be used to look up the {@link OAuth2AuthorizedClient}.
	 * @param clientRegistrationId the {@link ClientRegistration#getRegistrationId()
	 * clientRegistrationId} to be used to look up the {@link OAuth2AuthorizedClient}
	 * @return the {@link Consumer} to populate the attributes
	 */
	public static Consumer<Map<String, Object>> clientRegistrationId(String clientRegistrationId) {
		Assert.hasText(clientRegistrationId, "clientRegistrationId cannot be empty");
		return (attributes) -> attributes.put(CLIENT_REGISTRATION_ID_ATTR_NAME, clientRegistrationId);
	}

	private ClientAttributes() {
	}

}
