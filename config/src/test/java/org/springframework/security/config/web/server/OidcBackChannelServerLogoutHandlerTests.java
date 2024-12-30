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

package org.springframework.security.config.web.server;

import org.junit.jupiter.api.Test;

import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.security.oauth2.client.oidc.authentication.logout.TestOidcLogoutTokens;
import org.springframework.security.oauth2.client.oidc.server.session.InMemoryReactiveOidcSessionRegistry;
import org.springframework.security.oauth2.client.oidc.server.session.ReactiveOidcSessionRegistry;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link OidcBackChannelServerLogoutHandler}
 */
public class OidcBackChannelServerLogoutHandlerTests {

	private final ReactiveOidcSessionRegistry sessionRegistry = new InMemoryReactiveOidcSessionRegistry();

	private final OidcBackChannelLogoutAuthentication token = new OidcBackChannelLogoutAuthentication(
			TestOidcLogoutTokens.withSubject("issuer", "subject").build(),
			TestClientRegistrations.clientRegistration().build());

	// gh-14553
	@Test
	public void computeLogoutEndpointWhenDifferentHostnameThenLocalhost() {
		OidcBackChannelServerLogoutHandler logoutHandler = new OidcBackChannelServerLogoutHandler(this.sessionRegistry);
		logoutHandler.setLogoutUri("{baseScheme}://localhost{basePort}/logout");
		MockServerHttpRequest request = MockServerHttpRequest
			.get("https://host.docker.internal:8090/back-channel/logout")
			.build();
		String endpoint = logoutHandler.computeLogoutEndpoint(request, this.token);
		assertThat(endpoint).startsWith("https://localhost:8090/logout");
	}

	@Test
	public void computeLogoutEndpointWhenUsingBaseUrlTemplateThenServerName() {
		OidcBackChannelServerLogoutHandler logoutHandler = new OidcBackChannelServerLogoutHandler(this.sessionRegistry);
		logoutHandler.setLogoutUri("{baseUrl}/logout");
		MockServerHttpRequest request = MockServerHttpRequest
			.get("http://host.docker.internal:8090/back-channel/logout")
			.build();
		String endpoint = logoutHandler.computeLogoutEndpoint(request, this.token);
		assertThat(endpoint).startsWith("http://host.docker.internal:8090/logout");
	}

	// gh-14609
	@Test
	public void computeLogoutEndpointWhenLogoutUriThenUses() {
		OidcBackChannelServerLogoutHandler logoutHandler = new OidcBackChannelServerLogoutHandler(this.sessionRegistry);
		logoutHandler.setLogoutUri("http://localhost:8090/logout");
		MockServerHttpRequest request = MockServerHttpRequest.get("https://server-one.com/back-channel/logout").build();
		String endpoint = logoutHandler.computeLogoutEndpoint(request, this.token);
		assertThat(endpoint).startsWith("http://localhost:8090/logout");
	}

}
