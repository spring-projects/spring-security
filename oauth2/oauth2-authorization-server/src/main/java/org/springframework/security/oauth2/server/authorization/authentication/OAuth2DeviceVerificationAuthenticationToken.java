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
import org.springframework.util.Assert;

/**
 * An {@link Authentication} implementation for the Device Verification Request
 * (submission of the user code) used in the OAuth 2.0 Device Authorization Grant.
 *
 * @author Steve Riesenberg
 * @since 7.0
 * @see AbstractAuthenticationToken
 * @see OAuth2DeviceVerificationAuthenticationProvider
 */
public class OAuth2DeviceVerificationAuthenticationToken extends AbstractAuthenticationToken {

	@Serial
	private static final long serialVersionUID = -2164261941629756913L;

	private final Authentication principal;

	private final String userCode;

	private final Map<String, Object> additionalParameters;

	private final String clientId;

	/**
	 * Constructs an {@code OAuth2DeviceVerificationAuthenticationToken} using the
	 * provided parameters.
	 * @param principal the {@code Principal} (Resource Owner)
	 * @param userCode the user code associated with the device authorization response
	 * @param additionalParameters the additional parameters
	 */
	public OAuth2DeviceVerificationAuthenticationToken(Authentication principal, String userCode,
			@Nullable Map<String, Object> additionalParameters) {
		super(Collections.emptyList());
		Assert.notNull(principal, "principal cannot be null");
		Assert.hasText(userCode, "userCode cannot be empty");
		this.principal = principal;
		this.userCode = userCode;
		this.additionalParameters = Collections.unmodifiableMap(
				(additionalParameters != null) ? new HashMap<>(additionalParameters) : Collections.emptyMap());
		this.clientId = null;
	}

	/**
	 * Constructs an {@code OAuth2DeviceVerificationAuthenticationToken} using the
	 * provided parameters.
	 * @param principal the {@code Principal} (Resource Owner)
	 * @param userCode the user code associated with the device authorization response
	 * @param clientId the client identifier
	 */
	public OAuth2DeviceVerificationAuthenticationToken(Authentication principal, String userCode, String clientId) {
		super(Collections.emptyList());
		Assert.notNull(principal, "principal cannot be null");
		Assert.hasText(userCode, "userCode cannot be empty");
		Assert.hasText(clientId, "clientId cannot be empty");
		this.principal = principal;
		this.userCode = userCode;
		this.clientId = clientId;
		this.additionalParameters = Collections.emptyMap();
		setAuthenticated(true);
	}

	@Override
	public Object getPrincipal() {
		return this.principal;
	}

	@Override
	public Object getCredentials() {
		return "";
	}

	/**
	 * Returns the user code.
	 * @return the user code
	 */
	public String getUserCode() {
		return this.userCode;
	}

	/**
	 * Returns the additional parameters.
	 * @return the additional parameters, or an empty {@code Map} if not available
	 */
	public Map<String, Object> getAdditionalParameters() {
		return this.additionalParameters;
	}

	/**
	 * Returns the client identifier.
	 * @return the client identifier
	 */
	public String getClientId() {
		return this.clientId;
	}

}
