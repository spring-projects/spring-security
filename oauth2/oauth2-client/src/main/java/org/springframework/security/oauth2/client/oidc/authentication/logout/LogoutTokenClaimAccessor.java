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

package org.springframework.security.oauth2.client.oidc.authentication.logout;

import java.net.URL;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import org.springframework.security.oauth2.core.ClaimAccessor;

/**
 * A {@link ClaimAccessor} for the &quot;claims&quot; that can be returned in OIDC Logout
 * Tokens
 *
 * @author Josh Cummings
 * @since 6.2
 * @see OidcLogoutToken
 * @see <a target="_blank" href=
 * "https://openid.net/specs/openid-connect-backchannel-1_0.html#LogoutToken">OIDC
 * Back-Channel Logout Token</a>
 */
public interface LogoutTokenClaimAccessor extends ClaimAccessor {

	/**
	 * Returns the Issuer identifier {@code (iss)}.
	 * @return the Issuer identifier
	 */
	default URL getIssuer() {
		return this.getClaimAsURL(LogoutTokenClaimNames.ISS);
	}

	/**
	 * Returns the Subject identifier {@code (sub)}.
	 * @return the Subject identifier
	 */
	default String getSubject() {
		return this.getClaimAsString(LogoutTokenClaimNames.SUB);
	}

	/**
	 * Returns the Audience(s) {@code (aud)} that this ID Token is intended for.
	 * @return the Audience(s) that this ID Token is intended for
	 */
	default List<String> getAudience() {
		return this.getClaimAsStringList(LogoutTokenClaimNames.AUD);
	}

	/**
	 * Returns the time at which the ID Token was issued {@code (iat)}.
	 * @return the time at which the ID Token was issued
	 */
	default Instant getIssuedAt() {
		return this.getClaimAsInstant(LogoutTokenClaimNames.IAT);
	}

	/**
	 * Returns a {@link Map} that identifies this token as a logout token
	 * @return the identifying {@link Map}
	 */
	default Map<String, Object> getEvents() {
		return getClaimAsMap(LogoutTokenClaimNames.EVENTS);
	}

	/**
	 * Returns a {@code String} value {@code (sid)} representing the OIDC Provider session
	 * @return the value representing the OIDC Provider session
	 */
	default String getSessionId() {
		return getClaimAsString(LogoutTokenClaimNames.SID);
	}

	/**
	 * Returns the JWT ID {@code (jti)} claim which provides a unique identifier for the
	 * JWT.
	 * @return the JWT ID claim which provides a unique identifier for the JWT
	 */
	default String getId() {
		return this.getClaimAsString(LogoutTokenClaimNames.JTI);
	}

}
