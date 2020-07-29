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

package org.springframework.security.oauth2.client;

import org.springframework.security.oauth2.core.OAuth2Error;

/**
 * This exception is thrown when an OAuth 2.0 Client is required to obtain authorization
 * from the Resource Owner.
 *
 * @author Joe Grandja
 * @since 5.1
 * @see OAuth2AuthorizedClient
 */
public class ClientAuthorizationRequiredException extends ClientAuthorizationException {

	private static final String CLIENT_AUTHORIZATION_REQUIRED_ERROR_CODE = "client_authorization_required";

	/**
	 * Constructs a {@code ClientAuthorizationRequiredException} using the provided
	 * parameters.
	 * @param clientRegistrationId the identifier for the client's registration
	 */
	public ClientAuthorizationRequiredException(String clientRegistrationId) {
		super(new OAuth2Error(CLIENT_AUTHORIZATION_REQUIRED_ERROR_CODE,
				"Authorization required for Client Registration Id: " + clientRegistrationId, null),
				clientRegistrationId);
	}

}
