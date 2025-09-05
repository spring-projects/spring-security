/*
 * Copyright 2020-2025 the original author or authors.
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
import java.util.Map;

import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.Transient;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.util.Assert;

/**
 * An {@link Authentication} implementation used for OAuth 2.0 Client Authentication.
 *
 * @author Joe Grandja
 * @author Patryk Kostrzewa
 * @author Anoop Garlapati
 * @since 0.0.1
 * @see AbstractAuthenticationToken
 * @see RegisteredClient
 * @see JwtClientAssertionAuthenticationProvider
 * @see ClientSecretAuthenticationProvider
 * @see PublicClientAuthenticationProvider
 */
@Transient
public class OAuth2ClientAuthenticationToken extends AbstractAuthenticationToken {

	@Serial
	private static final long serialVersionUID = -7150784632941221304L;

	private final String clientId;

	private final RegisteredClient registeredClient;

	private final ClientAuthenticationMethod clientAuthenticationMethod;

	private final Object credentials;

	private final Map<String, Object> additionalParameters;

	/**
	 * Constructs an {@code OAuth2ClientAuthenticationToken} using the provided
	 * parameters.
	 * @param clientId the client identifier
	 * @param clientAuthenticationMethod the authentication method used by the client
	 * @param credentials the client credentials
	 * @param additionalParameters the additional parameters
	 */
	public OAuth2ClientAuthenticationToken(String clientId, ClientAuthenticationMethod clientAuthenticationMethod,
			@Nullable Object credentials, @Nullable Map<String, Object> additionalParameters) {
		super(Collections.emptyList());
		Assert.hasText(clientId, "clientId cannot be empty");
		Assert.notNull(clientAuthenticationMethod, "clientAuthenticationMethod cannot be null");
		this.clientId = clientId;
		this.registeredClient = null;
		this.clientAuthenticationMethod = clientAuthenticationMethod;
		this.credentials = credentials;
		this.additionalParameters = Collections
			.unmodifiableMap((additionalParameters != null) ? additionalParameters : Collections.emptyMap());
	}

	/**
	 * Constructs an {@code OAuth2ClientAuthenticationToken} using the provided
	 * parameters.
	 * @param registeredClient the authenticated registered client
	 * @param clientAuthenticationMethod the authentication method used by the client
	 * @param credentials the client credentials
	 */
	public OAuth2ClientAuthenticationToken(RegisteredClient registeredClient,
			ClientAuthenticationMethod clientAuthenticationMethod, @Nullable Object credentials) {
		super(Collections.emptyList());
		Assert.notNull(registeredClient, "registeredClient cannot be null");
		Assert.notNull(clientAuthenticationMethod, "clientAuthenticationMethod cannot be null");
		this.clientId = registeredClient.getClientId();
		this.registeredClient = registeredClient;
		this.clientAuthenticationMethod = clientAuthenticationMethod;
		this.credentials = credentials;
		this.additionalParameters = Collections.emptyMap();
		setAuthenticated(true);
	}

	@Override
	public Object getPrincipal() {
		return this.clientId;
	}

	@Nullable
	@Override
	public Object getCredentials() {
		return this.credentials;
	}

	/**
	 * Returns the authenticated {@link RegisteredClient registered client}, or
	 * {@code null} if not authenticated.
	 * @return the authenticated {@link RegisteredClient}, or {@code null} if not
	 * authenticated
	 */
	@Nullable
	public RegisteredClient getRegisteredClient() {
		return this.registeredClient;
	}

	/**
	 * Returns the {@link ClientAuthenticationMethod authentication method} used by the
	 * client.
	 * @return the {@link ClientAuthenticationMethod} used by the client
	 */
	public ClientAuthenticationMethod getClientAuthenticationMethod() {
		return this.clientAuthenticationMethod;
	}

	/**
	 * Returns the additional parameters.
	 * @return the additional parameters
	 */
	public Map<String, Object> getAdditionalParameters() {
		return this.additionalParameters;
	}

}
