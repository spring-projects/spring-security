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

package org.springframework.security.oauth2.server.resource.introspection;

import java.net.URL;
import java.time.Instant;
import java.util.List;

import org.springframework.security.oauth2.core.ClaimAccessor;

/**
 * A {@link ClaimAccessor} for the &quot;claims&quot; that may be contained
 * in the Introspection Response.
 *
 * @author David Kovac
 * @since 5.4
 * @see ClaimAccessor
 * @see OAuth2IntrospectionClaimNames
 * @see OAuth2IntrospectionAuthenticatedPrincipal
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7662#section-2.2">Introspection Response</a>
 */
public interface OAuth2IntrospectionClaimAccessor extends ClaimAccessor {
	/**
	 * Returns the indicator {@code (active)} whether or not the token is currently active
	 *
	 * @return the indicator whether or not the token is currently active
	 */
	default boolean isActive() {
		return Boolean.TRUE.equals(this.getClaimAsBoolean(OAuth2IntrospectionClaimNames.ACTIVE));
	}

	/**
	 * Returns the scopes {@code (scope)} associated with the token
	 *
	 * @return the scopes associated with the token
	 */
	default String getScope() {
		return this.getClaimAsString(OAuth2IntrospectionClaimNames.SCOPE);
	}

	/**
	 * Returns the client identifier {@code (client_id)} for the token
	 *
	 * @return the client identifier for the token
	 */
	default String getClientId() {
		return this.getClaimAsString(OAuth2IntrospectionClaimNames.CLIENT_ID);
	}

	/**
	 * Returns a human-readable identifier {@code (username)} for the resource owner that authorized the token
	 *
	 * @return a human-readable identifier for the resource owner that authorized the token
	 */
	default String getUsername() {
		return this.getClaimAsString(OAuth2IntrospectionClaimNames.USERNAME);
	}

	/**
	 * Returns the type of the token {@code (token_type)}, for example {@code bearer}.
	 *
	 * @return the type of the token, for example {@code bearer}.
	 */
	default String getTokenType() {
		return this.getClaimAsString(OAuth2IntrospectionClaimNames.TOKEN_TYPE);
	}

	/**
	 * Returns a timestamp {@code (exp)} indicating when the token expires
	 *
	 * @return a timestamp indicating when the token expires
	 */
	default Instant getExpiresAt() {
		return this.getClaimAsInstant(OAuth2IntrospectionClaimNames.EXPIRES_AT);
	}

	/**
	 * Returns a timestamp {@code (iat)} indicating when the token was issued
	 *
	 * @return a timestamp indicating when the token was issued
	 */
	default Instant getIssuedAt() {
		return this.getClaimAsInstant(OAuth2IntrospectionClaimNames.ISSUED_AT);
	}

	/**
	 * Returns a timestamp {@code (nbf)} indicating when the token is not to be used before
	 *
	 * @return a timestamp indicating when the token is not to be used before
	 */
	default Instant getNotBefore() {
		return this.getClaimAsInstant(OAuth2IntrospectionClaimNames.NOT_BEFORE);
	}

	/**
	 * Returns usually a machine-readable identifier {@code (sub)} of the resource owner who authorized the token
	 *
	 * @return usually a machine-readable identifier of the resource owner who authorized the token
	 */
	default String getSubject() {
		return this.getClaimAsString(OAuth2IntrospectionClaimNames.SUBJECT);
	}

	/**
	 * Returns the intended audience {@code (aud)} for the token
	 *
	 * @return the intended audience for the token
	 */
	default List<String> getAudience() {
		return this.getClaimAsStringList(OAuth2IntrospectionClaimNames.AUDIENCE);
	}

	/**
	 * Returns the issuer {@code (iss)} of the token
	 *
	 * @return the issuer of the token
	 */
	default URL getIssuer() {
		return this.getClaimAsURL(OAuth2IntrospectionClaimNames.ISSUER);
	}

	/**
	 * Returns the identifier {@code (jti)} for the token
	 *
	 * @return the identifier for the token
	 */
	default String getId() {
		return this.getClaimAsString(OAuth2IntrospectionClaimNames.JTI);
	}
}
