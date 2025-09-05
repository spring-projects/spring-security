/*
 * Copyright 2020-2022 the original author or authors.
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

import java.util.Collections;
import java.util.Map;

import org.junit.jupiter.api.Test;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link OAuth2AuthorizationCodeAuthenticationToken}.
 *
 * @author Joe Grandja
 * @author Daniel Garnier-Moiroux
 */
public class OAuth2AuthorizationCodeAuthenticationTokenTests {

	private String code = "code";

	private RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();

	private OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(this.registeredClient,
			ClientAuthenticationMethod.CLIENT_SECRET_BASIC, this.registeredClient.getClientSecret());

	private String redirectUri = "redirectUri";

	private Map<String, Object> additionalParameters = Collections.singletonMap("param1", "value1");

	@Test
	public void constructorWhenCodeNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2AuthorizationCodeAuthenticationToken(null, this.clientPrincipal,
				this.redirectUri, null))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("code cannot be empty");
	}

	@Test
	public void constructorWhenClientPrincipalNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(
				() -> new OAuth2AuthorizationCodeAuthenticationToken(this.code, null, this.redirectUri, null))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("clientPrincipal cannot be null");
	}

	@Test
	public void constructorWhenClientPrincipalProvidedThenCreated() {
		OAuth2AuthorizationCodeAuthenticationToken authentication = new OAuth2AuthorizationCodeAuthenticationToken(
				this.code, this.clientPrincipal, this.redirectUri, this.additionalParameters);
		assertThat(authentication.getGrantType()).isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE);
		assertThat(authentication.getPrincipal()).isEqualTo(this.clientPrincipal);
		assertThat(authentication.getCredentials().toString()).isEmpty();
		assertThat(authentication.getCode()).isEqualTo(this.code);
		assertThat(authentication.getRedirectUri()).isEqualTo(this.redirectUri);
		assertThat(authentication.getAdditionalParameters()).isEqualTo(this.additionalParameters);
	}

	@Test
	public void getAdditionalParametersWhenUpdateThenThrowUnsupportedOperationException() {
		OAuth2AuthorizationCodeAuthenticationToken authentication = new OAuth2AuthorizationCodeAuthenticationToken(
				this.code, this.clientPrincipal, this.redirectUri, this.additionalParameters);
		assertThatThrownBy(() -> authentication.getAdditionalParameters().put("another_key", 1))
			.isInstanceOf(UnsupportedOperationException.class);
		assertThatThrownBy(() -> authentication.getAdditionalParameters().remove("some_key"))
			.isInstanceOf(UnsupportedOperationException.class);
		assertThatThrownBy(() -> authentication.getAdditionalParameters().clear())
			.isInstanceOf(UnsupportedOperationException.class);
	}

}
