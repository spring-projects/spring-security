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

package org.springframework.security.oauth2.core;

import java.io.Serial;
import java.time.Instant;

/**
 * An implementation of an {@link AbstractOAuth2Token} representing a device code as part
 * of the OAuth 2.0 Device Authorization Grant.
 *
 * @author Steve Riesenberg
 * @since 6.1
 * @see OAuth2UserCode
 * @see <a target="_blank" href= "https://tools.ietf.org/html/rfc8628#section-3.2">Section
 * 3.2 Device Authorization Response</a>
 */
public class OAuth2DeviceCode extends AbstractOAuth2Token {

	@Serial
	private static final long serialVersionUID = -864134962034523562L;

	/**
	 * Constructs an {@code OAuth2DeviceCode} using the provided parameters.
	 * @param tokenValue the token value
	 * @param issuedAt the time at which the token was issued
	 * @param expiresAt the time at which the token expires
	 */
	public OAuth2DeviceCode(String tokenValue, Instant issuedAt, Instant expiresAt) {
		super(tokenValue, issuedAt, expiresAt);
	}

}
