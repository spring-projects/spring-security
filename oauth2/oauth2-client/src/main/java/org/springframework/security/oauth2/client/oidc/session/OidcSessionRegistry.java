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

package org.springframework.security.oauth2.client.oidc.session;

import org.springframework.security.oauth2.client.oidc.authentication.logout.OidcLogoutToken;

/**
 * A registry to record the tie between the OIDC Provider session and the Client session.
 * This is handy when a provider makes a logout request that indicates the OIDC Provider
 * session or the End User.
 *
 * @author Josh Cummings
 * @since 6.2
 * @see <a target="_blank" href=
 * "https://openid.net/specs/openid-connect-backchannel-1_0.html#LogoutToken">Logout
 * Token</a>
 */
public interface OidcSessionRegistry {

	/**
	 * Register a OIDC Provider session with the provided client session. Generally
	 * speaking, the client session should be the session tied to the current login.
	 * @param info the {@link OidcSessionInformation} to use
	 */
	void saveSessionInformation(OidcSessionInformation info);

	/**
	 * Deregister the OIDC Provider session tied to the provided client session. Generally
	 * speaking, the client session should be the session tied to the current logout.
	 * @param clientSessionId the client session
	 * @return any found {@link OidcSessionInformation}, could be {@code null}
	 */
	OidcSessionInformation removeSessionInformation(String clientSessionId);

	/**
	 * Deregister the OIDC Provider sessions referenced by the provided OIDC Logout Token
	 * by its session id or its subject. Note that the issuer and audience should also
	 * match the corresponding values found in each {@link OidcSessionInformation}
	 * returned.
	 * @param logoutToken the {@link OidcLogoutToken}
	 * @return any found {@link OidcSessionInformation}s, could be empty
	 */
	Iterable<OidcSessionInformation> removeSessionInformation(OidcLogoutToken logoutToken);

}
