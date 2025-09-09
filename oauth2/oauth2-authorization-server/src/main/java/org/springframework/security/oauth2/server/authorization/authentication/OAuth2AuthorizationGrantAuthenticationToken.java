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

package org.springframework.security.oauth2.server.authorization.authentication;

import java.io.Serial;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.util.Assert;

/**
 * Base implementation of an {@link Authentication} representing an OAuth 2.0
 * Authorization Grant.
 *
 * @author Joe Grandja
 * @since 7.0
 * @see AbstractAuthenticationToken
 * @see AuthorizationGrantType
 * @see OAuth2ClientAuthenticationToken
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-1.3">Section
 * 1.3 Authorization Grant</a>
 */
public class OAuth2AuthorizationGrantAuthenticationToken extends AbstractAuthenticationToken {

	@Serial
	private static final long serialVersionUID = -1715946281123199051L;

	private final AuthorizationGrantType authorizationGrantType;

	private final Authentication clientPrincipal;

	private final Map<String, Object> additionalParameters;

	/**
	 * Sub-class constructor.
	 * @param authorizationGrantType the authorization grant type
	 * @param clientPrincipal the authenticated client principal
	 * @param additionalParameters the additional parameters
	 */
	protected OAuth2AuthorizationGrantAuthenticationToken(AuthorizationGrantType authorizationGrantType,
			Authentication clientPrincipal, @Nullable Map<String, Object> additionalParameters) {
		super(Collections.emptyList());
		Assert.notNull(authorizationGrantType, "authorizationGrantType cannot be null");
		Assert.notNull(clientPrincipal, "clientPrincipal cannot be null");
		this.authorizationGrantType = authorizationGrantType;
		this.clientPrincipal = clientPrincipal;
		this.additionalParameters = Collections.unmodifiableMap(
				(additionalParameters != null) ? new HashMap<>(additionalParameters) : Collections.emptyMap());
	}

	/**
	 * Returns the authorization grant type.
	 * @return the authorization grant type
	 */
	public AuthorizationGrantType getGrantType() {
		return this.authorizationGrantType;
	}

	@Override
	public Object getPrincipal() {
		return this.clientPrincipal;
	}

	@Override
	public Object getCredentials() {
		return "";
	}

	/**
	 * Returns the additional parameters.
	 * @return the additional parameters
	 */
	public Map<String, Object> getAdditionalParameters() {
		return this.additionalParameters;
	}

}
