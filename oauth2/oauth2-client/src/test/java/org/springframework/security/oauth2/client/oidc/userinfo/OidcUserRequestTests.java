/*
 * Copyright 2002-2017 the original author or authors.
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
package org.springframework.security.oauth2.client.oidc.userinfo;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link OidcUserRequest}.
 *
 * @author Joe Grandja
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest(ClientRegistration.class)
public class OidcUserRequestTests {
	private ClientRegistration clientRegistration;
	private OAuth2AccessToken accessToken;
	private OidcIdToken idToken;

	@Before
	public void setUp() {
		this.clientRegistration = mock(ClientRegistration.class);
		this.accessToken = mock(OAuth2AccessToken.class);
		this.idToken = mock(OidcIdToken.class);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorWhenClientRegistrationIsNullThenThrowIllegalArgumentException() {
		new OidcUserRequest(null, this.accessToken, this.idToken);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorWhenAccessTokenIsNullThenThrowIllegalArgumentException() {
		new OidcUserRequest(this.clientRegistration, null, this.idToken);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorWhenIdTokenIsNullThenThrowIllegalArgumentException() {
		new OidcUserRequest(this.clientRegistration, this.accessToken, null);
	}

	@Test
	public void constructorWhenAllParametersProvidedAndValidThenCreated() {
		OidcUserRequest userRequest = new OidcUserRequest(
			this.clientRegistration, this.accessToken, this.idToken);

		assertThat(userRequest.getClientRegistration()).isEqualTo(this.clientRegistration);
		assertThat(userRequest.getAccessToken()).isEqualTo(this.accessToken);
		assertThat(userRequest.getIdToken()).isEqualTo(this.idToken);
	}
}
