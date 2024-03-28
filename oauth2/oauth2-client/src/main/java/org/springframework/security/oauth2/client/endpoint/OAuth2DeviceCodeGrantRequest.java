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

package org.springframework.security.oauth2.client.endpoint;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

/**
 * An OAuth 2.0 Device Authorization Grant request that holds the Device Code in
 * {@link #getClientRegistration()}.
 *
 * @author Max Batischev
 * @since 6.3
 * @see <a target="_blank" href=
 * "https://datatracker.ietf.org/doc/html/rfc8628#section-3.4">Section 3.4 Device Access
 * Token Request</a>
 * @see AbstractOAuth2AuthorizationGrantRequest
 * @see ClientRegistration
 */
public class OAuth2DeviceCodeGrantRequest extends AbstractOAuth2AuthorizationGrantRequest {

	private final String deviceCode;

	/**
	 * Constructs an {@code OAuth2AuthorizationCodeGrantRequest} using the provided
	 * parameters.
	 * @param clientRegistration the client registration
	 * @param deviceCode the device code
	 * @since 6.3
	 */
	public OAuth2DeviceCodeGrantRequest(ClientRegistration clientRegistration, String deviceCode) {
		super(AuthorizationGrantType.DEVICE_CODE, clientRegistration);
		this.deviceCode = deviceCode;
	}

	public String getDeviceCode() {
		return this.deviceCode;
	}

}
