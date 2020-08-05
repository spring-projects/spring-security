/*
 * Copyright 2002-2020 the original author or authors.
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

import org.junit.Test;

import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.TestOAuth2AccessTokens;
import org.springframework.security.oauth2.core.TestOAuth2RefreshTokens;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.entry;

/**
 * Tests for {@link OAuth2AuthorizeRequest}.
 *
 * @author Joe Grandja
 */
public class OAuth2AuthorizeRequestTests {

	private ClientRegistration clientRegistration = TestClientRegistrations.clientRegistration().build();

	private Authentication principal = new TestingAuthenticationToken("principal", "password");

	private OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(this.clientRegistration,
			this.principal.getName(), TestOAuth2AccessTokens.scopes("read", "write"),
			TestOAuth2RefreshTokens.refreshToken());

	@Test
	public void withClientRegistrationIdWhenClientRegistrationIdIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> OAuth2AuthorizeRequest.withClientRegistrationId(null))
				.isInstanceOf(IllegalArgumentException.class).hasMessage("clientRegistrationId cannot be empty");
	}

	@Test
	public void withAuthorizedClientWhenAuthorizedClientIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> OAuth2AuthorizeRequest.withAuthorizedClient(null))
				.isInstanceOf(IllegalArgumentException.class).hasMessage("authorizedClient cannot be null");
	}

	@Test
	public void withClientRegistrationIdWhenPrincipalIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> OAuth2AuthorizeRequest
				.withClientRegistrationId(this.clientRegistration.getRegistrationId()).build())
						.isInstanceOf(IllegalArgumentException.class).hasMessage("principal cannot be null");
	}

	@Test
	public void withClientRegistrationIdWhenPrincipalNameIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> OAuth2AuthorizeRequest
				.withClientRegistrationId(this.clientRegistration.getRegistrationId()).principal((String) null).build())
						.isInstanceOf(IllegalArgumentException.class).hasMessage("principalName cannot be empty");
	}

	@Test
	public void withClientRegistrationIdWhenAllValuesProvidedThenAllValuesAreSet() {
		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
				.withClientRegistrationId(this.clientRegistration.getRegistrationId()).principal(this.principal)
				.attributes(attrs -> {
					attrs.put("name1", "value1");
					attrs.put("name2", "value2");
				}).build();

		assertThat(authorizeRequest.getClientRegistrationId()).isEqualTo(this.clientRegistration.getRegistrationId());
		assertThat(authorizeRequest.getAuthorizedClient()).isNull();
		assertThat(authorizeRequest.getPrincipal()).isEqualTo(this.principal);
		assertThat(authorizeRequest.getAttributes()).contains(entry("name1", "value1"), entry("name2", "value2"));
	}

	@Test
	public void withAuthorizedClientWhenAllValuesProvidedThenAllValuesAreSet() {
		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest.withAuthorizedClient(this.authorizedClient)
				.principal(this.principal).attributes(attrs -> {
					attrs.put("name1", "value1");
					attrs.put("name2", "value2");
				}).build();

		assertThat(authorizeRequest.getClientRegistrationId())
				.isEqualTo(this.authorizedClient.getClientRegistration().getRegistrationId());
		assertThat(authorizeRequest.getAuthorizedClient()).isEqualTo(this.authorizedClient);
		assertThat(authorizeRequest.getPrincipal()).isEqualTo(this.principal);
		assertThat(authorizeRequest.getAttributes()).contains(entry("name1", "value1"), entry("name2", "value2"));
	}

	@Test
	public void withClientRegistrationIdWhenPrincipalNameProvidedThenPrincipalCreated() {
		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
				.withClientRegistrationId(this.clientRegistration.getRegistrationId()).principal("principalName")
				.build();

		assertThat(authorizeRequest.getClientRegistrationId()).isEqualTo(this.clientRegistration.getRegistrationId());
		assertThat(authorizeRequest.getAuthorizedClient()).isNull();
		assertThat(authorizeRequest.getPrincipal().getName()).isEqualTo("principalName");
	}

}
