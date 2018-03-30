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
package org.springframework.security.oauth2.client;

import org.springframework.util.Assert;

/**
 * This exception is thrown when an OAuth 2.0 Client is required
 * to obtain authorization from the Resource Owner.
 *
 * @author Joe Grandja
 * @since 5.1
 * @see OAuth2AuthorizedClient
 */
public class ClientAuthorizationRequiredException extends OAuth2ClientException {
	private final String clientRegistrationId;

	/**
	 * Constructs a {@code ClientAuthorizationRequiredException} using the provided parameters.
	 *
	 * @param clientRegistrationId the identifier for the client's registration
	 */
	public ClientAuthorizationRequiredException(String clientRegistrationId) {
		this(clientRegistrationId, "Authorization required for Client Registration Id: " + clientRegistrationId);
	}

	/**
	 * Constructs a {@code ClientAuthorizationRequiredException} using the provided parameters.
	 *
	 * @param clientRegistrationId the identifier for the client's registration
	 * @param message the detail message
	 */
	public ClientAuthorizationRequiredException(String clientRegistrationId, String message) {
		super(message);
		Assert.hasText(clientRegistrationId, "clientRegistrationId cannot be empty");
		this.clientRegistrationId = clientRegistrationId;
	}

	/**
	 * Returns the identifier for the client's registration.
	 *
	 * @return the identifier for the client's registration
	 */
	public String getClientRegistrationId() {
		return this.clientRegistrationId;
	}
}
