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
package org.springframework.security.oauth2.core.endpoint;

import org.junit.Test;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests {@link AuthorizationCodeTokenRequestAttributes}
 *
 * @author Luander Ribeiro
 */
public class AuthorizationCodeTokenRequestAttributesTest {
	private static final String CODE = "code";
	private static final String CLIENT_ID = "client id";
	private static final String REDIRECT_URI = "http://redirect.uri/";

	@Test(expected = IllegalArgumentException.class)
	public void buildWhenCodeIsNullThenThrowIllegalArgumentException() {
		AuthorizationCodeTokenRequestAttributes
			.withCode(null)
			.clientId(CLIENT_ID)
			.redirectUri(REDIRECT_URI)
			.build();
	}

	@Test(expected = IllegalArgumentException.class)
	public void buildWhenClientIdIsNullThenThrowIllegalArgumentException() {
		AuthorizationCodeTokenRequestAttributes
			.withCode(CODE)
			.clientId(null)
			.redirectUri(REDIRECT_URI)
			.build();
	}

	@Test(expected = IllegalArgumentException.class)
	public void buildWhenRedirectUriIsNullThenThrowIllegalArgumentException() {
		AuthorizationCodeTokenRequestAttributes
			.withCode(CODE)
			.clientId(CLIENT_ID)
			.redirectUri(null)
			.build();
	}

	@Test(expected = IllegalArgumentException.class)
	public void buildWhenClientIdNotSetThenThrowIllegalArgumentException() {
		AuthorizationCodeTokenRequestAttributes
			.withCode(CODE)
			.redirectUri(REDIRECT_URI)
			.build();
	}

	@Test(expected = IllegalArgumentException.class)
	public void buildWhenRedirectUriNotSetThenThrowIllegalArgumentException() {
		AuthorizationCodeTokenRequestAttributes
			.withCode(CODE)
			.clientId(CLIENT_ID)
			.build();
	}
}
