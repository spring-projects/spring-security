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
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2DeviceCode;
import org.springframework.security.oauth2.core.OAuth2UserCode;
import org.springframework.util.Assert;

/**
 * An {@link Authentication} implementation for the Device Authorization Request used in
 * the OAuth 2.0 Device Authorization Grant.
 *
 * @author Steve Riesenberg
 * @since 7.0
 * @see AbstractAuthenticationToken
 * @see OAuth2ClientAuthenticationToken
 * @see OAuth2DeviceAuthorizationRequestAuthenticationProvider
 */
public class OAuth2DeviceAuthorizationRequestAuthenticationToken extends AbstractAuthenticationToken {

	@Serial
	private static final long serialVersionUID = -561059025431630645L;

	private final Authentication clientPrincipal;

	private final String authorizationUri;

	private final Set<String> scopes;

	private final OAuth2DeviceCode deviceCode;

	private final OAuth2UserCode userCode;

	private final Map<String, Object> additionalParameters;

	/**
	 * Constructs an {@code OAuth2DeviceAuthorizationRequestAuthenticationToken} using the
	 * provided parameters.
	 * @param clientPrincipal the authenticated client principal
	 * @param authorizationUri the authorization {@code URI}
	 * @param scopes the requested scope(s)
	 * @param additionalParameters the additional parameters
	 */
	public OAuth2DeviceAuthorizationRequestAuthenticationToken(Authentication clientPrincipal, String authorizationUri,
			@Nullable Set<String> scopes, @Nullable Map<String, Object> additionalParameters) {
		super(Collections.emptyList());
		Assert.notNull(clientPrincipal, "clientPrincipal cannot be null");
		Assert.hasText(authorizationUri, "authorizationUri cannot be empty");
		this.clientPrincipal = clientPrincipal;
		this.authorizationUri = authorizationUri;
		this.scopes = Collections.unmodifiableSet((scopes != null) ? new HashSet<>(scopes) : Collections.emptySet());
		this.additionalParameters = Collections.unmodifiableMap(
				(additionalParameters != null) ? new HashMap<>(additionalParameters) : Collections.emptyMap());
		this.deviceCode = null;
		this.userCode = null;
	}

	/**
	 * Constructs an {@code OAuth2DeviceAuthorizationRequestAuthenticationToken} using the
	 * provided parameters.
	 * @param clientPrincipal the authenticated client principal
	 * @param scopes the requested scope(s)
	 * @param deviceCode the {@link OAuth2DeviceCode}
	 * @param userCode the {@link OAuth2UserCode}
	 */
	public OAuth2DeviceAuthorizationRequestAuthenticationToken(Authentication clientPrincipal,
			@Nullable Set<String> scopes, OAuth2DeviceCode deviceCode, OAuth2UserCode userCode) {
		super(Collections.emptyList());
		Assert.notNull(clientPrincipal, "clientPrincipal cannot be null");
		Assert.notNull(deviceCode, "deviceCode cannot be null");
		Assert.notNull(userCode, "userCode cannot be null");
		this.clientPrincipal = clientPrincipal;
		this.scopes = Collections.unmodifiableSet((scopes != null) ? new HashSet<>(scopes) : Collections.emptySet());
		this.deviceCode = deviceCode;
		this.userCode = userCode;
		this.authorizationUri = null;
		this.additionalParameters = Collections.emptyMap();
		setAuthenticated(true);
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
	 * Returns the authorization {@code URI}.
	 * @return the authorization {@code URI}
	 */
	public String getAuthorizationUri() {
		return this.authorizationUri;
	}

	/**
	 * Returns the requested scope(s).
	 * @return the requested scope(s)
	 */
	public Set<String> getScopes() {
		return this.scopes;
	}

	/**
	 * Returns the device code.
	 * @return the device code
	 */
	public OAuth2DeviceCode getDeviceCode() {
		return this.deviceCode;
	}

	/**
	 * Returns the user code.
	 * @return the user code
	 */
	public OAuth2UserCode getUserCode() {
		return this.userCode;
	}

	/**
	 * Returns the additional parameters.
	 * @return the additional parameters
	 */
	public Map<String, Object> getAdditionalParameters() {
		return this.additionalParameters;
	}

}
