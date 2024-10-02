/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.oauth2.client.web.client;

import java.util.Map;
import java.util.function.Consumer;

import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.util.Assert;

/**
 * A strategy for resolving a {@code clientRegistrationId} from an intercepted request
 * using {@link ClientHttpRequest#getAttributes() attributes}.
 *
 * @author Steve Riesenberg
 * @since 6.4
 * @see OAuth2ClientHttpRequestInterceptor
 */
public final class RequestAttributeClientRegistrationIdResolver
		implements OAuth2ClientHttpRequestInterceptor.ClientRegistrationIdResolver {

	private static final String CLIENT_REGISTRATION_ID_ATTR_NAME = RequestAttributeClientRegistrationIdResolver.class
		.getName()
		.concat(".clientRegistrationId");

	@Override
	public String resolve(HttpRequest request) {
		return (String) request.getAttributes().get(CLIENT_REGISTRATION_ID_ATTR_NAME);
	}

	/**
	 * Modifies the {@link ClientHttpRequest#getAttributes() attributes} to include the
	 * {@link ClientRegistration#getRegistrationId() clientRegistrationId} to be used to
	 * look up the {@link OAuth2AuthorizedClient}.
	 * @param clientRegistrationId the {@link ClientRegistration#getRegistrationId()
	 * clientRegistrationId} to be used to look up the {@link OAuth2AuthorizedClient}
	 * @return the {@link Consumer} to populate the attributes
	 */
	public static Consumer<Map<String, Object>> clientRegistrationId(String clientRegistrationId) {
		Assert.hasText(clientRegistrationId, "clientRegistrationId cannot be empty");
		return (attributes) -> attributes.put(CLIENT_REGISTRATION_ID_ATTR_NAME, clientRegistrationId);
	}

}
