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

import org.springframework.security.oauth2.client.oidc.authentication.logout.OidcLogoutToken;

/**
 * A registry to record the tie between the OIDC Provider session and the Client session.
 * This is handy when a provider makes a logout request that indicates the OIDC Provider
 * session or the End User.
 *
 * @author Josh Cummings
 * @since 6.1
 * @see <a target="_blank" href=
 * "https://openid.net/specs/openid-connect-backchannel-1_0.html#LogoutToken">Logout
 * Token</a>
 */
public interface OidcProviderSessionRegistry {

	/**
	 * Register a OIDC Provider session with the provided client session. Generally
	 * speaking, the client session should be the session tied to the current login.
	 * @param details the {@link OidcProviderSessionRegistrationDetails} to use
	 */
	void register(OidcProviderSessionRegistrationDetails details);

	/**
	 * Update the entry for a Client when their session id changes. This is handy, for
	 * example, when the id changes for session fixation protection.
	 * @param oldClientSessionId the Client's old session id
	 * @param newClientSessionId the Client's new session id
	 */
	void reregister(String oldClientSessionId, String newClientSessionId);

	/**
	 * Deregister the OIDC Provider session tied to the provided client session. Generally
	 * speaking, the client session should be the session tied to the current logout.
	 * @param clientSessionId the client session
	 * @return any found {@link OidcProviderSessionRegistrationDetails}, could be
	 * {@code null}
	 */
	OidcProviderSessionRegistrationDetails deregister(String clientSessionId);

	/**
	 * Deregister the OIDC Provider sessions referenced by the provided OIDC Logout Token
	 * by its session id or its subject.
	 * @param logoutToken the {@link OidcLogoutToken}
	 * @return any found {@link OidcProviderSessionRegistrationDetails}s, could be empty
	 */
	Iterable<OidcProviderSessionRegistrationDetails> deregister(OidcLogoutToken logoutToken);

}
