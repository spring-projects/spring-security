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
package org.springframework.security.test.oauth2.reactive.server;

import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockAuthentication;

import java.util.Map;

import org.springframework.http.client.reactive.ClientHttpConnector;
import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.test.oauth2.support.OidcIdTokenAuthenticationBuilder;
import org.springframework.test.web.reactive.server.MockServerConfigurer;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.test.web.reactive.server.WebTestClientConfigurer;
import org.springframework.web.server.adapter.WebHttpHandlerBuilder;

/**
 * @author Jérôme Wacongne &lt;ch4mp@c4-soft.com&gt;
 * @since 5.2.0
 */
public class OidcIdTokenMutator extends OidcIdTokenAuthenticationBuilder<OidcIdTokenMutator>
		implements
		WebTestClientConfigurer,
		MockServerConfigurer {

	private final ClientRegistrationMutator clientRegistrationMutator;
	private final AuthorizationRequestMutator authorizationRequestMutator;

	public OidcIdTokenMutator(final AuthorizationGrantType authorizationGrantType) {
		super(authorizationGrantType);
		clientRegistrationMutator = new ClientRegistrationMutator(this, clientRegistrationBuilder);
		authorizationRequestMutator = new AuthorizationRequestMutator(this, authorizationRequestBuilder, claims);
	}

	public ClientRegistrationMutator clientRegistration() {
		return clientRegistrationMutator;
	}

	public AuthorizationRequestMutator authorizationRequest() {
		return authorizationRequestMutator;
	}

	@Override
	public void beforeServerCreated(final WebHttpHandlerBuilder builder) {
		configurer().beforeServerCreated(builder);
	}

	@Override
	public void afterConfigureAdded(final WebTestClient.MockServerSpec<?> serverSpec) {
		configurer().afterConfigureAdded(serverSpec);
	}

	@Override
	public void afterConfigurerAdded(
			final WebTestClient.Builder builder,
			@Nullable final WebHttpHandlerBuilder httpHandlerBuilder,
			@Nullable final ClientHttpConnector connector) {
		configurer().afterConfigurerAdded(builder, httpHandlerBuilder, connector);
	}

	private <T extends WebTestClientConfigurer & MockServerConfigurer> T configurer() {
		return mockAuthentication(build());
	}

	public final class ClientRegistrationMutator extends ClientRegistrationBuilder<ClientRegistrationMutator>
			implements
			WebTestClientConfigurer,
			MockServerConfigurer {
		private final OidcIdTokenMutator root;

		public ClientRegistrationMutator(final OidcIdTokenMutator root, final ClientRegistration.Builder delegate) {
			super(delegate);
			this.root = root;
		}

		@Override
		public void beforeServerCreated(final WebHttpHandlerBuilder builder) {
			root.beforeServerCreated(builder);
		}

		@Override
		public void afterConfigureAdded(final WebTestClient.MockServerSpec<?> serverSpec) {
			root.afterConfigureAdded(serverSpec);
		}

		@Override
		public void afterConfigurerAdded(
				final WebTestClient.Builder builder,
				@Nullable final WebHttpHandlerBuilder httpHandlerBuilder,
				@Nullable final ClientHttpConnector connector) {
			root.afterConfigurerAdded(builder, httpHandlerBuilder, connector);
		}

	}

	public final class AuthorizationRequestMutator extends AuthorizationRequestBuilder<AuthorizationRequestMutator>
			implements
			WebTestClientConfigurer,
			MockServerConfigurer {
		private final OidcIdTokenMutator root;

		public AuthorizationRequestMutator(
				final OidcIdTokenMutator root,
				final OAuth2AuthorizationRequest.Builder delegate,
				final Map<String, Object> additionalParameters) {
			super(delegate, additionalParameters);
			this.root = root;
		}

		@Override
		public void beforeServerCreated(final WebHttpHandlerBuilder builder) {
			root.beforeServerCreated(builder);
		}

		@Override
		public void afterConfigureAdded(final WebTestClient.MockServerSpec<?> serverSpec) {
			root.afterConfigureAdded(serverSpec);
		}

		@Override
		public void afterConfigurerAdded(
				final WebTestClient.Builder builder,
				@Nullable final WebHttpHandlerBuilder httpHandlerBuilder,
				@Nullable final ClientHttpConnector connector) {
			root.afterConfigurerAdded(builder, httpHandlerBuilder, connector);
		}

	}

}
