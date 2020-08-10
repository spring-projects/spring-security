/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.oauth2.client.web.server;

import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.TestOAuth2AccessTokens;
import org.springframework.web.server.ServerWebExchange;

import static org.assertj.core.api.Assertions.*;

/**
 * @author Rob Winch
 */
public class UnAuthenticatedServerOAuth2AuthorizedClientRepositoryTests {

	private UnAuthenticatedServerOAuth2AuthorizedClientRepository repository = new UnAuthenticatedServerOAuth2AuthorizedClientRepository();

	private ClientRegistration clientRegistration = TestClientRegistrations.clientCredentials().build();

	private String clientRegistrationId = this.clientRegistration.getRegistrationId();

	private ServerWebExchange exchange;

	private Authentication anonymous = new AnonymousAuthenticationToken("key", "anonymous",
			AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));

	private Authentication authentication;

	private OAuth2AuthorizedClient authorizedClient;

	@Before
	public void setup() {
		OAuth2AccessToken token = TestOAuth2AccessTokens.noScopes();
		this.authorizedClient = new OAuth2AuthorizedClient(this.clientRegistration, "anonymousUser", token);
	}

	// loadAuthorizedClient

	@Test
	public void loadAuthorizedClientWhenClientRegistrationIdNullThenIllegalArgumentException() {
		this.clientRegistrationId = null;
		assertThatThrownBy(() -> this.repository
				.loadAuthorizedClient(this.clientRegistrationId, this.authentication, this.exchange).block())
						.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void loadAuthorizedClientWhenAuthenticationNotNullThenIllegalArgumentException() {
		this.authentication = new TestingAuthenticationToken("a", "b", "ROLE_USER");
		assertThatThrownBy(() -> this.repository
				.loadAuthorizedClient(this.clientRegistrationId, this.authentication, this.exchange).block())
						.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void loadAuthorizedClientWhenServerWebExchangeNotNullThenIllegalArgumentException() {
		this.exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/").build());
		assertThatThrownBy(() -> this.repository
				.loadAuthorizedClient(this.clientRegistrationId, this.authentication, this.exchange).block())
						.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void loadAuthorizedClientWhenNotFoundThenEmpty() {
		assertThat(this.repository.loadAuthorizedClient(this.clientRegistrationId, this.authentication, this.exchange)
				.block()).isNull();
	}

	@Test
	public void loadAuthorizedClientWhenFoundThenFound() {
		this.repository.saveAuthorizedClient(this.authorizedClient, this.authentication, this.exchange).block();

		assertThat(this.repository.loadAuthorizedClient(this.clientRegistrationId, this.authentication, this.exchange)
				.block()).isEqualTo(this.authorizedClient);
	}

	@Test
	public void loadAuthorizedClientWhenMultipleThenFound() {
		ClientRegistration otherClientRegistration = TestClientRegistrations.clientRegistration()
				.registrationId("other-client-registration").build();
		OAuth2AuthorizedClient otherAuthorizedClient = new OAuth2AuthorizedClient(otherClientRegistration,
				"anonymousUser", this.authorizedClient.getAccessToken());

		this.repository.saveAuthorizedClient(this.authorizedClient, this.authentication, this.exchange).block();
		this.repository.saveAuthorizedClient(otherAuthorizedClient, this.authentication, this.exchange).block();

		assertThat(this.repository.loadAuthorizedClient(this.clientRegistrationId, this.authentication, this.exchange)
				.block()).isEqualTo(this.authorizedClient);
	}

	@Test
	public void loadAuthorizedClientWhenAnonymousThenFound() {
		this.authentication = this.anonymous;
		this.repository.saveAuthorizedClient(this.authorizedClient, this.authentication, this.exchange).block();

		assertThat(this.repository.loadAuthorizedClient(this.clientRegistrationId, this.authentication, this.exchange)
				.block()).isEqualTo(this.authorizedClient);
	}

	// saveAuthorizedClient

	@Test
	public void saveAuthorizedClientWhenAuthorizedClientNullThenIllegalArgumentException() {
		this.authorizedClient = null;
		assertThatThrownBy(() -> this.repository
				.saveAuthorizedClient(this.authorizedClient, this.authentication, this.exchange).block())
						.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void saveAuthorizedClientWhenAuthenticationNotNullThenIllegalArgumentException() {
		this.authentication = new TestingAuthenticationToken("a", "b", "ROLE_USER");
		assertThatThrownBy(() -> this.repository
				.saveAuthorizedClient(this.authorizedClient, this.authentication, this.exchange).block())
						.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void saveAuthorizedClientWhenServerWebExchangeNotNullThenIllegalArgumentException() {
		this.exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/").build());
		assertThatThrownBy(() -> this.repository
				.saveAuthorizedClient(this.authorizedClient, this.authentication, this.exchange).block())
						.isInstanceOf(IllegalArgumentException.class);
	}

	// removeAuthorizedClient

	@Test
	public void removeAuthorizedClientWhenClientRegistrationIdNullThenIllegalArgumentException() {
		this.clientRegistrationId = null;
		assertThatThrownBy(() -> this.repository
				.removeAuthorizedClient(this.clientRegistrationId, this.authentication, this.exchange).block())
						.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void removeAuthorizedClientWhenAuthenticationNotNullThenIllegalArgumentException() {
		this.authentication = new TestingAuthenticationToken("a", "b", "ROLE_USER");
		assertThatThrownBy(() -> this.repository
				.removeAuthorizedClient(this.clientRegistrationId, this.authentication, this.exchange).block())
						.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void removeAuthorizedClientWhenServerWebExchangeNotNullThenIllegalArgumentException() {
		this.exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/").build());
		assertThatThrownBy(() -> this.repository
				.removeAuthorizedClient(this.clientRegistrationId, this.authentication, this.exchange).block())
						.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void removeAuthorizedClientWhenFoundThenFound() {
		this.repository.saveAuthorizedClient(this.authorizedClient, this.authentication, this.exchange).block();
		this.repository.removeAuthorizedClient(this.clientRegistrationId, this.authentication, this.exchange).block();

		assertThat(this.repository.loadAuthorizedClient(this.clientRegistrationId, this.authentication, this.exchange)
				.block()).isNull();
	}

}
