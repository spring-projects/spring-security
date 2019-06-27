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
package org.springframework.security.oauth2.client;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.TestOAuth2AccessTokens;

import static org.assertj.core.api.Assertions.*;

/**
 * Tests for {@link OAuth2AuthorizationContext}.
 *
 * @author Joe Grandja
 */
public class OAuth2AuthorizationContextTests {
	private ClientRegistration clientRegistration;
	private OAuth2AuthorizedClient authorizedClient;
	private Authentication principal;

	@Before
	public void setup() {
		this.clientRegistration = TestClientRegistrations.clientRegistration().build();
		this.authorizedClient = new OAuth2AuthorizedClient(
				this.clientRegistration, "principal", TestOAuth2AccessTokens.scopes("read", "write"));
		this.principal = new TestingAuthenticationToken("principal", "password");
	}

	@Test
	public void forClientWhenClientRegistrationIdIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> OAuth2AuthorizationContext.forClient(null).build())
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("clientRegistrationId cannot be empty");
	}

	@Test
	public void forClientWhenPrincipalIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> OAuth2AuthorizationContext.forClient(this.clientRegistration.getRegistrationId()).build())
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("principal cannot be null");
	}

	@Test
	public void forClientWhenPrincipalNameIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> OAuth2AuthorizationContext.forClient(this.clientRegistration.getRegistrationId())
				.principal((String) null)
				.build())
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("principalName cannot be empty");
	}

	@Test
	public void forClientWhenAllValuesProvidedThenAllValuesAreSet() {
		OAuth2AuthorizationContext authorizationContext = OAuth2AuthorizationContext.forClient(this.clientRegistration.getRegistrationId())
				.principal(this.principal)
				.attribute("attribute1", "value1")
				.attribute("attribute2", "value2")
				.build();
		assertThat(authorizationContext.getClientRegistrationId()).isSameAs(this.clientRegistration.getRegistrationId());
		assertThat(authorizationContext.getPrincipal()).isSameAs(this.principal);
		assertThat(authorizationContext.getAttributes()).contains(
				entry("attribute1", "value1"), entry("attribute2", "value2"));
	}
}
