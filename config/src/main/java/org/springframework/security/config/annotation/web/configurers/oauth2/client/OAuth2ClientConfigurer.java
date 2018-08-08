/*
 * Copyright 2002-2018 the original author or authors.
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
package org.springframework.security.config.annotation.web.configurers.oauth2.client;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthorizationCodeAuthenticationProvider;
import org.springframework.security.oauth2.client.endpoint.NimbusAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.AuthenticatedPrincipalOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationCodeGrantFilter;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.util.Assert;

/**
 * An {@link AbstractHttpConfigurer} for OAuth 2.0 Client support.
 *
 * <p>
 * The following configuration options are available:
 *
 * <ul>
 * <li>{@link #authorizationCodeGrant()} - enables the OAuth 2.0 Authorization Code Grant</li>
 * </ul>
 *
 * <p>
 * Defaults are provided for all configuration options with the only required configuration
 * being {@link #clientRegistrationRepository(ClientRegistrationRepository)}.
 * Alternatively, a {@link ClientRegistrationRepository} {@code @Bean} may be registered instead.
 *
 * <h2>Security Filters</h2>
 *
 * The following {@code Filter}'s are populated when {@link #authorizationCodeGrant()} is configured:
 *
 * <ul>
 * <li>{@link OAuth2AuthorizationRequestRedirectFilter}</li>
 * <li>{@link OAuth2AuthorizationCodeGrantFilter}</li>
 * </ul>
 *
 * <h2>Shared Objects Created</h2>
 *
 * The following shared objects are populated:
 *
 * <ul>
 * <li>{@link ClientRegistrationRepository} (required)</li>
 * <li>{@link OAuth2AuthorizedClientRepository} (optional)</li>
 * </ul>
 *
 * <h2>Shared Objects Used</h2>
 *
 * The following shared objects are used:
 *
 * <ul>
 * <li>{@link ClientRegistrationRepository}</li>
 * <li>{@link OAuth2AuthorizedClientRepository}</li>
 * </ul>
 *
 * @author Joe Grandja
 * @since 5.1
 * @see OAuth2AuthorizationRequestRedirectFilter
 * @see OAuth2AuthorizationCodeGrantFilter
 * @see ClientRegistrationRepository
 * @see OAuth2AuthorizedClientRepository
 * @see AbstractHttpConfigurer
 */
public final class OAuth2ClientConfigurer<B extends HttpSecurityBuilder<B>> extends
	AbstractHttpConfigurer<OAuth2ClientConfigurer<B>, B> {

	private AuthorizationCodeGrantConfigurer authorizationCodeGrantConfigurer;

	/**
	 * Sets the repository of client registrations.
	 *
	 * @param clientRegistrationRepository the repository of client registrations
	 * @return the {@link OAuth2ClientConfigurer} for further configuration
	 */
	public OAuth2ClientConfigurer<B> clientRegistrationRepository(ClientRegistrationRepository clientRegistrationRepository) {
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		this.getBuilder().setSharedObject(ClientRegistrationRepository.class, clientRegistrationRepository);
		return this;
	}

	/**
	 * Sets the repository for authorized client(s).
	 *
	 * @param authorizedClientRepository the authorized client repository
	 * @return the {@link OAuth2ClientConfigurer} for further configuration
	 */
	public OAuth2ClientConfigurer<B> authorizedClientRepository(OAuth2AuthorizedClientRepository authorizedClientRepository) {
		Assert.notNull(authorizedClientRepository, "authorizedClientRepository cannot be null");
		this.getBuilder().setSharedObject(OAuth2AuthorizedClientRepository.class, authorizedClientRepository);
		return this;
	}

	/**
	 * Sets the service for authorized client(s).
	 *
	 * @param authorizedClientService the authorized client service
	 * @return the {@link OAuth2ClientConfigurer} for further configuration
	 */
	public OAuth2ClientConfigurer<B> authorizedClientService(OAuth2AuthorizedClientService authorizedClientService) {
		Assert.notNull(authorizedClientService, "authorizedClientService cannot be null");
		this.authorizedClientRepository(new AuthenticatedPrincipalOAuth2AuthorizedClientRepository(authorizedClientService));
		return this;
	}

	/**
	 * Returns the {@link AuthorizationCodeGrantConfigurer} for configuring the OAuth 2.0 Authorization Code Grant.
	 *
	 * @return the {@link AuthorizationCodeGrantConfigurer}
	 */
	public AuthorizationCodeGrantConfigurer authorizationCodeGrant() {
		if (this.authorizationCodeGrantConfigurer == null) {
			this.authorizationCodeGrantConfigurer = new AuthorizationCodeGrantConfigurer();
		}
		return this.authorizationCodeGrantConfigurer;
	}

	/**
	 * Configuration options for the OAuth 2.0 Authorization Code Grant.
	 */
	public class AuthorizationCodeGrantConfigurer {
		private final AuthorizationEndpointConfig authorizationEndpointConfig = new AuthorizationEndpointConfig();
		private final TokenEndpointConfig tokenEndpointConfig = new TokenEndpointConfig();

		private AuthorizationCodeGrantConfigurer() {
		}

		/**
		 * Returns the {@link AuthorizationEndpointConfig} for configuring the Authorization Server's Authorization Endpoint.
		 *
		 * @return the {@link AuthorizationEndpointConfig}
		 */
		public AuthorizationEndpointConfig authorizationEndpoint() {
			return this.authorizationEndpointConfig;
		}

		/**
		 * Configuration options for the Authorization Server's Authorization Endpoint.
		 */
		public class AuthorizationEndpointConfig {
			private String authorizationRequestBaseUri;
			private OAuth2AuthorizationRequestResolver authorizationRequestResolver;
			private AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository;

			private AuthorizationEndpointConfig() {
			}

			/**
			 * Sets the base {@code URI} used for authorization requests.
			 *
			 * @param authorizationRequestBaseUri the base {@code URI} used for authorization requests
			 * @return the {@link AuthorizationEndpointConfig} for further configuration
			 */
			public AuthorizationEndpointConfig baseUri(String authorizationRequestBaseUri) {
				Assert.hasText(authorizationRequestBaseUri, "authorizationRequestBaseUri cannot be empty");
				this.authorizationRequestBaseUri = authorizationRequestBaseUri;
				return this;
			}

			/**
			 * Sets the resolver used for resolving {@link OAuth2AuthorizationRequest}'s.
			 *
			 * @param authorizationRequestResolver the resolver used for resolving {@link OAuth2AuthorizationRequest}'s
			 * @return the {@link AuthorizationEndpointConfig} for further configuration
			 */
			public AuthorizationEndpointConfig authorizationRequestResolver(OAuth2AuthorizationRequestResolver authorizationRequestResolver) {
				Assert.notNull(authorizationRequestResolver, "authorizationRequestResolver cannot be null");
				this.authorizationRequestResolver = authorizationRequestResolver;
				return this;
			}

			/**
			 * Sets the repository used for storing {@link OAuth2AuthorizationRequest}'s.
			 *
			 * @param authorizationRequestRepository the repository used for storing {@link OAuth2AuthorizationRequest}'s
			 * @return the {@link AuthorizationEndpointConfig} for further configuration
			 */
			public AuthorizationEndpointConfig authorizationRequestRepository(
				AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository) {

				Assert.notNull(authorizationRequestRepository, "authorizationRequestRepository cannot be null");
				this.authorizationRequestRepository = authorizationRequestRepository;
				return this;
			}

			/**
			 * Returns the {@link AuthorizationCodeGrantConfigurer} for further configuration.
			 *
			 * @return the {@link AuthorizationCodeGrantConfigurer}
			 */
			public AuthorizationCodeGrantConfigurer and() {
				return AuthorizationCodeGrantConfigurer.this;
			}
		}

		/**
		 * Returns the {@link TokenEndpointConfig} for configuring the Authorization Server's Token Endpoint.
		 *
		 * @return the {@link TokenEndpointConfig}
		 */
		public TokenEndpointConfig tokenEndpoint() {
			return this.tokenEndpointConfig;
		}

		/**
		 * Configuration options for the Authorization Server's Token Endpoint.
		 */
		public class TokenEndpointConfig {
			private OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient;

			private TokenEndpointConfig() {
			}

			/**
			 * Sets the client used for requesting the access token credential from the Token Endpoint.
			 *
			 * @param accessTokenResponseClient the client used for requesting the access token credential from the Token Endpoint
			 * @return the {@link TokenEndpointConfig} for further configuration
			 */
			public TokenEndpointConfig accessTokenResponseClient(
				OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient) {

				Assert.notNull(accessTokenResponseClient, "accessTokenResponseClient cannot be null");
				this.accessTokenResponseClient = accessTokenResponseClient;
				return this;
			}

			/**
			 * Returns the {@link AuthorizationCodeGrantConfigurer} for further configuration.
			 *
			 * @return the {@link AuthorizationCodeGrantConfigurer}
			 */
			public AuthorizationCodeGrantConfigurer and() {
				return AuthorizationCodeGrantConfigurer.this;
			}
		}

		/**
		 * Returns the {@link OAuth2ClientConfigurer} for further configuration.
		 *
		 * @return the {@link OAuth2ClientConfigurer}
		 */
		public OAuth2ClientConfigurer<B> and() {
			return OAuth2ClientConfigurer.this;
		}

		private void configure(B builder) {
			OAuth2AuthorizationRequestRedirectFilter authorizationRequestFilter;

			if (this.authorizationEndpointConfig.authorizationRequestResolver != null) {
				authorizationRequestFilter = new OAuth2AuthorizationRequestRedirectFilter(
						this.authorizationEndpointConfig.authorizationRequestResolver);
			} else {
				String authorizationRequestBaseUri = this.authorizationEndpointConfig.authorizationRequestBaseUri;
				if (authorizationRequestBaseUri == null) {
					authorizationRequestBaseUri = OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI;
				}
				authorizationRequestFilter = new OAuth2AuthorizationRequestRedirectFilter(
						OAuth2ClientConfigurerUtils.getClientRegistrationRepository(builder), authorizationRequestBaseUri);
			}

			if (this.authorizationEndpointConfig.authorizationRequestRepository != null) {
				authorizationRequestFilter.setAuthorizationRequestRepository(
						this.authorizationEndpointConfig.authorizationRequestRepository);
			}
			RequestCache requestCache = builder.getSharedObject(RequestCache.class);
			if (requestCache != null) {
				authorizationRequestFilter.setRequestCache(requestCache);
			}
			builder.addFilter(postProcess(authorizationRequestFilter));

			AuthenticationManager authenticationManager = builder.getSharedObject(AuthenticationManager.class);

			OAuth2AuthorizationCodeGrantFilter authorizationCodeGrantFilter = new OAuth2AuthorizationCodeGrantFilter(
					OAuth2ClientConfigurerUtils.getClientRegistrationRepository(builder),
					OAuth2ClientConfigurerUtils.getAuthorizedClientRepository(builder),
					authenticationManager);

			if (this.authorizationEndpointConfig.authorizationRequestRepository != null) {
				authorizationCodeGrantFilter.setAuthorizationRequestRepository(
						this.authorizationEndpointConfig.authorizationRequestRepository);
			}
			builder.addFilter(postProcess(authorizationCodeGrantFilter));
		}
	}

	@Override
	public void init(B builder) throws Exception {
		if (this.authorizationCodeGrantConfigurer != null) {
			this.init(builder, this.authorizationCodeGrantConfigurer);
		}
	}

	@Override
	public void configure(B builder) throws Exception {
		if (this.authorizationCodeGrantConfigurer != null) {
			this.authorizationCodeGrantConfigurer.configure(builder);
		}
	}

	private void init(B builder, AuthorizationCodeGrantConfigurer authorizationCodeGrantConfigurer) throws Exception {
		OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient =
			authorizationCodeGrantConfigurer.tokenEndpointConfig.accessTokenResponseClient;
		if (accessTokenResponseClient == null) {
			accessTokenResponseClient = new NimbusAuthorizationCodeTokenResponseClient();
		}

		OAuth2AuthorizationCodeAuthenticationProvider authorizationCodeAuthenticationProvider =
			new OAuth2AuthorizationCodeAuthenticationProvider(accessTokenResponseClient);
		builder.authenticationProvider(this.postProcess(authorizationCodeAuthenticationProvider));
	}
}
