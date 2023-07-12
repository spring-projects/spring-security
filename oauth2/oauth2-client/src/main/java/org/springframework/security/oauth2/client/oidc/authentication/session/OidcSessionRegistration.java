/*
 * Copyright 2002-2023 the original author or authors.
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

package org.springframework.security.oauth2.client.oidc.authentication.session;

import java.util.Map;

import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

/**
 * The default implementation for {@link OidcSessionRegistration}. Handy for in-memory
 * registries.
 *
 * @author Josh Cummings
 * @since 6.2
 */
public class OidcSessionRegistration extends SessionInformation {

	private String clientRegistrationId;

	/**
	 * Construct an {@link OidcSessionRegistration}
	 * @param sessionId the Client's session id
	 * @param additionalHeaders any additional headers needed to authenticate session
	 * ownership
	 * @param user the OIDC Provider's session and end user
	 */
	public OidcSessionRegistration(String clientId, String sessionId, Map<String, String> additionalHeaders,
			OidcUser user) {
		super(user, sessionId, additionalHeaders);
		this.clientRegistrationId = clientId;
	}

	public String getClientId() {
		return this.clientRegistrationId;
	}

	@Override
	public OidcUser getPrincipal() {
		return (OidcUser) super.getPrincipal();
	}

}
