/*
 * Copyright 2002-2019 the original author or authors.
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

import org.junit.Test;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link OAuth2PasswordGrantRequest}.
 *
 * @author Joe Grandja
 */
public class OAuth2PasswordGrantRequestTests {

	private ClientRegistration clientRegistration = TestClientRegistrations.clientRegistration()
			.authorizationGrantType(AuthorizationGrantType.PASSWORD).build();

	private String username = "user1";

	private String password = "password";

	@Test
	public void constructorWhenClientRegistrationIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2PasswordGrantRequest(null, this.username, this.password))
				.isInstanceOf(IllegalArgumentException.class).hasMessage("clientRegistration cannot be null");
	}

	@Test
	public void constructorWhenUsernameIsEmptyThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2PasswordGrantRequest(this.clientRegistration, null, this.password))
				.isInstanceOf(IllegalArgumentException.class).hasMessage("username cannot be empty");
		assertThatThrownBy(() -> new OAuth2PasswordGrantRequest(this.clientRegistration, "", this.password))
				.isInstanceOf(IllegalArgumentException.class).hasMessage("username cannot be empty");
	}

	@Test
	public void constructorWhenPasswordIsEmptyThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2PasswordGrantRequest(this.clientRegistration, this.username, null))
				.isInstanceOf(IllegalArgumentException.class).hasMessage("password cannot be empty");
		assertThatThrownBy(() -> new OAuth2PasswordGrantRequest(this.clientRegistration, this.username, ""))
				.isInstanceOf(IllegalArgumentException.class).hasMessage("password cannot be empty");
	}

	@Test
	public void constructorWhenClientRegistrationInvalidGrantTypeThenThrowIllegalArgumentException() {
		ClientRegistration registration = TestClientRegistrations.clientCredentials().build();
		assertThatThrownBy(() -> new OAuth2PasswordGrantRequest(registration, this.username, this.password))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("clientRegistration.authorizationGrantType must be AuthorizationGrantType.PASSWORD");
	}

	@Test
	public void constructorWhenValidParametersProvidedThenCreated() {
		OAuth2PasswordGrantRequest passwordGrantRequest = new OAuth2PasswordGrantRequest(this.clientRegistration,
				this.username, this.password);
		assertThat(passwordGrantRequest.getGrantType()).isEqualTo(AuthorizationGrantType.PASSWORD);
		assertThat(passwordGrantRequest.getClientRegistration()).isSameAs(this.clientRegistration);
		assertThat(passwordGrantRequest.getUsername()).isEqualTo(this.username);
		assertThat(passwordGrantRequest.getPassword()).isEqualTo(this.password);
	}

}
