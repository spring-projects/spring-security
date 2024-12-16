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

package org.springframework.security.oauth2.client.oidc.authentication.logout;

import java.io.Serial;
import java.time.Instant;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Consumer;

import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.util.Assert;

/**
 * An implementation of an {@link AbstractOAuth2Token} representing an OpenID Backchannel
 * Logout Token.
 *
 * <p>
 * The {@code OidcLogoutToken} is a security token that contains &quot;claims&quot; about
 * terminating sessions for a given OIDC Provider session id or End User.
 *
 * @author Josh Cummings
 * @since 6.2
 * @see AbstractOAuth2Token
 * @see LogoutTokenClaimAccessor
 * @see <a target="_blank" href=
 * "https://openid.net/specs/openid-connect-backchannel-1_0.html#LogoutToken">Logout
 * Token</a>
 */
public class OidcLogoutToken extends AbstractOAuth2Token implements LogoutTokenClaimAccessor {

	@Serial
	private static final long serialVersionUID = -5705409698230609696L;

	private static final String BACKCHANNEL_LOGOUT_TOKEN_EVENT_NAME = "http://schemas.openid.net/event/backchannel-logout";

	private final Map<String, Object> claims;

	/**
	 * Constructs a {@link OidcLogoutToken} using the provided parameters.
	 * @param tokenValue the Logout Token value
	 * @param issuedAt the time at which the Logout Token was issued {@code (iat)}
	 * @param claims the claims about the logout statement
	 */
	OidcLogoutToken(String tokenValue, Instant issuedAt, Map<String, Object> claims) {
		super(tokenValue, issuedAt, Instant.MAX);
		this.claims = Collections.unmodifiableMap(claims);
		Assert.notNull(claims, "claims must not be null");
	}

	@Override
	public Map<String, Object> getClaims() {
		return this.claims;
	}

	/**
	 * Create a {@link OidcLogoutToken.Builder} based on the given token value
	 * @param tokenValue the token value to use
	 * @return the {@link OidcLogoutToken.Builder} for further configuration
	 */
	public static Builder withTokenValue(String tokenValue) {
		return new Builder(tokenValue);
	}

	/**
	 * A builder for {@link OidcLogoutToken}s
	 *
	 * @author Josh Cummings
	 */
	public static final class Builder {

		private String tokenValue;

		private final Map<String, Object> claims = new LinkedHashMap<>();

		private Builder(String tokenValue) {
			this.tokenValue = tokenValue;
			this.claims.put(LogoutTokenClaimNames.EVENTS,
					Collections.singletonMap(BACKCHANNEL_LOGOUT_TOKEN_EVENT_NAME, Collections.emptyMap()));
		}

		/**
		 * Use this token value in the resulting {@link OidcLogoutToken}
		 * @param tokenValue The token value to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder tokenValue(String tokenValue) {
			this.tokenValue = tokenValue;
			return this;
		}

		/**
		 * Use this claim in the resulting {@link OidcLogoutToken}
		 * @param name The claim name
		 * @param value The claim value
		 * @return the {@link Builder} for further configurations
		 */
		public Builder claim(String name, Object value) {
			this.claims.put(name, value);
			return this;
		}

		/**
		 * Provides access to every {@link #claim(String, Object)} declared so far with
		 * the possibility to add, replace, or remove.
		 * @param claimsConsumer the consumer
		 * @return the {@link Builder} for further configurations
		 */
		public Builder claims(Consumer<Map<String, Object>> claimsConsumer) {
			claimsConsumer.accept(this.claims);
			return this;
		}

		/**
		 * Use this audience in the resulting {@link OidcLogoutToken}
		 * @param audience The audience(s) to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder audience(Collection<String> audience) {
			return claim(LogoutTokenClaimNames.AUD, audience);
		}

		/**
		 * Use this issued-at timestamp in the resulting {@link OidcLogoutToken}
		 * @param issuedAt The issued-at timestamp to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder issuedAt(Instant issuedAt) {
			return claim(LogoutTokenClaimNames.IAT, issuedAt);
		}

		/**
		 * Use this issuer in the resulting {@link OidcLogoutToken}
		 * @param issuer The issuer to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder issuer(String issuer) {
			return claim(LogoutTokenClaimNames.ISS, issuer);
		}

		/**
		 * Use this id to identify the resulting {@link OidcLogoutToken}
		 * @param jti The unique identifier to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder jti(String jti) {
			return claim(LogoutTokenClaimNames.JTI, jti);
		}

		/**
		 * Use this subject in the resulting {@link OidcLogoutToken}
		 * @param subject The subject to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder subject(String subject) {
			return claim(LogoutTokenClaimNames.SUB, subject);
		}

		/**
		 * A JSON object that identifies this token as a logout token
		 * @param events The JSON object to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder events(Map<String, Object> events) {
			return claim(LogoutTokenClaimNames.EVENTS, events);
		}

		/**
		 * Use this session id to correlate the OIDC Provider session
		 * @param sessionId The session id to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder sessionId(String sessionId) {
			return claim(LogoutTokenClaimNames.SID, sessionId);
		}

		public OidcLogoutToken build() {
			Assert.notNull(this.claims.get(LogoutTokenClaimNames.ISS), "issuer must not be null");
			Assert.isInstanceOf(Collection.class, this.claims.get(LogoutTokenClaimNames.AUD),
					"audience must be a collection");
			Assert.notEmpty((Collection<?>) this.claims.get(LogoutTokenClaimNames.AUD), "audience must not be empty");
			Assert.notNull(this.claims.get(LogoutTokenClaimNames.JTI), "jti must not be null");
			Assert.isTrue(hasLogoutTokenIdentifyingMember(),
					"logout token must contain an events claim that contains a member called " + "'"
							+ BACKCHANNEL_LOGOUT_TOKEN_EVENT_NAME + "' whose value is an empty Map");
			Assert.isNull(this.claims.get("nonce"), "logout token must not contain a nonce claim");
			Instant iat = toInstant(this.claims.get(IdTokenClaimNames.IAT));
			return new OidcLogoutToken(this.tokenValue, iat, this.claims);
		}

		private boolean hasLogoutTokenIdentifyingMember() {
			if (!(this.claims.get(LogoutTokenClaimNames.EVENTS) instanceof Map<?, ?> events)) {
				return false;
			}
			if (!(events.get(BACKCHANNEL_LOGOUT_TOKEN_EVENT_NAME) instanceof Map<?, ?> object)) {
				return false;
			}
			return object.isEmpty();
		}

		private Instant toInstant(Object timestamp) {
			if (timestamp != null) {
				Assert.isInstanceOf(Instant.class, timestamp, "timestamps must be of type Instant");
			}
			return (Instant) timestamp;
		}

	}

}
