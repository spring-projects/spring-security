/*
 * Copyright 2012-2017 the original author or authors.
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
package org.springframework.security.oauth2.core.protocol;

import org.springframework.security.oauth2.core.AccessToken;

import java.util.Collections;
import java.util.Set;

/**
 * @author Joe Grandja
 */
public class ImplicitGrantTokenResponseAttributes extends TokenResponseAttributes {
	private final String state;

	public ImplicitGrantTokenResponseAttributes(String accessToken, AccessToken.TokenType accessTokenType,
												long expiresIn, String state) {
		this(accessToken, accessTokenType, expiresIn, Collections.emptySet(), state);
	}

	public ImplicitGrantTokenResponseAttributes(String accessToken, AccessToken.TokenType accessTokenType, long expiresIn,
												Set<String> scopes, String state) {
		super(accessToken, accessTokenType, expiresIn, scopes, null);
		this.state = state;
	}

	public final String getState() {
		return this.state;
	}
}