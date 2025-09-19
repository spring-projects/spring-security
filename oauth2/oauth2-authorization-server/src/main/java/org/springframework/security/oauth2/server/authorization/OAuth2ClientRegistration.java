/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.oauth2.server.authorization;

import java.io.Serial;
import java.util.Map;

import org.springframework.util.Assert;

/**
 * A representation of an OAuth 2.0 Client Registration Request and Response, which is
 * sent to and returned from the Client Registration Endpoint, and contains a set of
 * claims about the Client's Registration information. The claims are defined by the OAuth
 * 2.0 Dynamic Client Registration Protocol specification.
 *
 * @author Joe Grandja
 * @since 7.0
 * @see AbstractOAuth2ClientRegistration
 * @see <a target="_blank" href=
 * "https://datatracker.ietf.org/doc/html/rfc7591#section-3.1">3.1. Client Registration
 * Request</a>
 * @see <a target="_blank" href=
 * "https://datatracker.ietf.org/doc/html/rfc7591#section-3.2.1">3.2.1. Client
 * Registration Response</a>
 */
public final class OAuth2ClientRegistration extends AbstractOAuth2ClientRegistration {

	@Serial
	private static final long serialVersionUID = 283805553286847831L;

	private OAuth2ClientRegistration(Map<String, Object> claims) {
		super(claims);
	}

	/**
	 * Constructs a new {@link Builder} with empty claims.
	 * @return the {@link Builder}
	 */
	public static Builder builder() {
		return new Builder();
	}

	/**
	 * Constructs a new {@link Builder} with the provided claims.
	 * @param claims the claims to initialize the builder
	 * @return the {@link Builder}
	 */
	public static Builder withClaims(Map<String, Object> claims) {
		Assert.notEmpty(claims, "claims cannot be empty");
		return new Builder().claims((c) -> c.putAll(claims));
	}

	/**
	 * Helps configure an {@link OAuth2ClientRegistration}.
	 */
	public static final class Builder extends AbstractBuilder<OAuth2ClientRegistration, Builder> {

		private Builder() {
		}

		/**
		 * Validate the claims and build the {@link OAuth2ClientRegistration}.
		 * @return the {@link OAuth2ClientRegistration}
		 */
		@Override
		public OAuth2ClientRegistration build() {
			validate();
			return new OAuth2ClientRegistration(getClaims());
		}

	}

}
