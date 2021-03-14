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
package org.springframework.security.oauth2.client.endpoint;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.Assert;

/**
 * A JWT Bearer Authorization Grant request that holds a trusted {@link #getJwt() JWT} credential,
 * which was granted by the Resource Owner to the {@link #getClientRegistration() Client}.
 *
 * @author Joe Grandja
 * @since 5.2
 * @see AbstractOAuth2AuthorizationGrantRequest
 * @see ClientRegistration
 * @see Jwt
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7523#section-2.1">Section 2.1 JWTs as Authorization Grants</a>
 */
public class JwtBearerGrantRequest extends AbstractOAuth2AuthorizationGrantRequest {
	public static final AuthorizationGrantType JWT_BEARER_GRANT_TYPE =
			new AuthorizationGrantType("urn:ietf:params:oauth:grant-type:jwt-bearer");
	private final ClientRegistration clientRegistration;
	private final Jwt jwt;

	/**
	 * Constructs an {@code JwtBearerGrantRequest} using the provided parameters.
	 *
	 * @param clientRegistration the client registration
	 * @param jwt the JWT Bearer token
	 */
	public JwtBearerGrantRequest(ClientRegistration clientRegistration, Jwt jwt) {
		super(JWT_BEARER_GRANT_TYPE);
		Assert.notNull(clientRegistration, "clientRegistration cannot be null");
		Assert.notNull(jwt, "jwt cannot be null");
		this.clientRegistration = clientRegistration;
		this.jwt = jwt;
	}

	/**
	 * Returns the {@link ClientRegistration client registration}.
	 *
	 * @return the {@link ClientRegistration}
	 */
	public ClientRegistration getClientRegistration() {
		return this.clientRegistration;
	}

	/**
	 * Returns the {@link Jwt JWT Bearer token}.
	 *
	 * @return the {@link Jwt}
	 */
	public Jwt getJwt() {
		return this.jwt;
	}
}
