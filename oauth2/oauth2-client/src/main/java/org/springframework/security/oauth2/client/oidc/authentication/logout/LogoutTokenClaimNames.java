/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.oauth2.client.oidc.authentication.logout;

/**
 * The names of the &quot;claims&quot; defined by the OpenID Back-Channel Logout 1.0
 * specification that can be returned in a Logout Token.
 *
 * @author Josh Cummings
 * @since 6.2
 * @see OidcLogoutToken
 * @see <a target="_blank" href=
 * "https://openid.net/specs/openid-connect-backchannel-1_0.html#LogoutToken">OIDC
 * Back-Channel Logout Token</a>
 */
public final class LogoutTokenClaimNames {

	/**
	 * {@code jti} - the JTI identifier
	 */
	public static final String JTI = "jti";

	/**
	 * {@code iss} - the Issuer identifier
	 */
	public static final String ISS = "iss";

	/**
	 * {@code sub} - the Subject identifier
	 */
	public static final String SUB = "sub";

	/**
	 * {@code aud} - the Audience(s) that the ID Token is intended for
	 */
	public static final String AUD = "aud";

	/**
	 * {@code iat} - the time at which the ID Token was issued
	 */
	public static final String IAT = "iat";

	/**
	 * {@code events} - a JSON object that identifies this token as a logout token
	 */
	public static final String EVENTS = "events";

	/**
	 * {@code sid} - the session id for the OIDC provider
	 */
	public static final String SID = "sid";

	private LogoutTokenClaimNames() {
	}

}
