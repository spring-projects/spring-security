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
package org.springframework.security.config.annotation.web.configurers.oauth2.client;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthorizationCodeAuthenticationProvider;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.AuthenticatedPrincipalOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
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
 * <li>{@link #authorizationCodeGrant()} - support for the OAuth 2.0 Authorization Code
 * Grant</li>
 * </ul>
 *
 * <p>
 * Defaults are provided for all configuration options with the only required
 * configuration being
 * {@link #clientRegistrationRepository(ClientRegistrationRepository)}. Alternatively, a
 * {@link ClientRegistrationRepository} {@code @Bean} may be registered instead.
 *
 * <h2>Security Filters</h2>
 *
 * The following {@code Filter}'s are populated for {@link #authorizationCodeGrant()}:
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
 * @author Parikshit Dutta
 * @since 5.1
 * @see OAuth2AuthorizationRequestRedirectFilter
 * @see OAuth2AuthorizationCodeGrantFilter
 * @see ClientRegistrationRepository
 * @see OAuth2AuthorizedClientRepository
 * @see AbstractHttpConfigurer
 */
public final class OAuth2ClientConfigurer<B extends HttpSecurityBuilder<B>>
		extends AbstractHttpConfigurer<OAuth2ClientConfigurer<B>, B> {

	private AuthorizationCodeGrantConfigurer authorizationCodeGrantConfigurer = new AuthorizationCodeGrantConfigurer();

	/**
	 * Sets the repository of client registrations.
	 * @param clientRegistrationRepository the repository of client registrations
	 * @return the {@link OAuth2ClientConfigurer} for further configuration
	 */
	public OAuth2ClientConfigurer<B> clientRegistrationRepository(
			ClientRegistrationRepository clientRegistrationRepository) {
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		this.getBuilder().setSharedObject(ClientRegistrationRepository.class, clientRegistrationRepository);
		return this;
	}

	/**
	 * Sets the repository for authorized client(s).
	 * @param authorizedClientRepository the authorized client repository
	 * @return the {@link OAuth2ClientConfigurer} for further configuration
	 */
	public OAuth2ClientConfigurer<B> authorizedClientRepository(
			OAuth2AuthorizedClientRepository authorizedClientRepository) {
		Assert.notNull(authorizedClientRepository, "authorizedClientRepository cannot be null");
		this.getBuilder().setSharedObject(OAuth2AuthorizedClientRepository.class, authorizedClientRepository);
		return this;
	}

	/**
	 * Sets the service for authorized client(s).
	 * @param authorizedClientService the authorized client service
	 * @return the {@link OAuth2ClientConfigurer} for further configuration
	 */
	public OAuth2ClientConfigurer<B> authorizedClientService(OAuth2AuthorizedClientService authorizedClientService) {
		Assert.notNull(authorizedClientService, "authorizedClientService cannot be null");
		this.authorizedClientRepository(
				new AuthenticatedPrincipalOAuth2AuthorizedClientRepository(authorizedClientService));
		return this;
	}

	/**
	 * Returns the {@link AuthorizationCodeGrantConfigurer} for configuring the OAuth 2.0
	 * Authorization Code Grant.
	 * @return the {@link AuthorizationCodeGrantConfigurer}
	 */
	public AuthorizationCodeGrantConfigurer authorizationCodeGrant() {
		return this.authorizationCodeGrantConfigurer;
	}

	/**
	 * Configures the OAuth 2.0 Authorization Code Grant.
	 * @param authorizationCodeGrantCustomizer the {@link Customizer} to provide more
	 * options for the {@link AuthorizationCodeGrantConfigurer}
	 * @return the {@link OAuth2ClientConfigurer} for further customizations
	 */
	public OAuth2ClientConfigurer<B> authorizationCodeGrant(
			Customizer<AuthorizationCodeGrantConfigurer> authorizationCodeGrantCustomizer) {
		authorizationCodeGrantCustomizer.customize(this.authorizationCodeGrantConfigurer);
		return this;
	}

	@Override
	public void init(B builder) {
		this.authorizationCodeGrantConfigurer.init(builder);
	}

	@Override
	public void configure(B builder) {
		this.authorizationCodeGrantConfigurer.configure(builder);
	}

	/**
	 * Configuration options for the OAuth 2.0 Authorization Code Grant.
	 */
	public final class AuthorizationCodeGrantConfigurer {

		private OAuth2AuthorizationRequestResolver authorizationRequestResolver;

		private AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository;

		private OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient;

		private AuthorizationCodeGrantConfigurer() {
		}

		/**
		 * Sets the resolver used for resolving {@link OAuth2AuthorizationRequest}'s.
		 * @param authorizationRequestResolver the resolver used for resolving
		 * {@link OAuth2AuthorizationRequest}'s
		 * @return the {@link AuthorizationCodeGrantConfigurer} for further configuration
		 */
		public AuthorizationCodeGrantConfigurer authorizationRequestResolver(
				OAuth2AuthorizationRequestResolver authorizationRequestResolver) {
			Assert.notNull(authorizationRequestResolver, "authorizationRequestResolver cannot be null");
			this.authorizationRequestResolver = authorizationRequestResolver;
			return this;
		}

		/**
		 * Sets the repository used for storing {@link OAuth2AuthorizationRequest}'s.
		 * @param authorizationRequestRepository the repository used for storing
		 * {@link OAuth2AuthorizationRequest}'s
		 * @return the {@link AuthorizationCodeGrantConfigurer} for further configuration
		 */
		public AuthorizationCodeGrantConfigurer authorizationRequestRepository(
				AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository) {

			Assert.notNull(authorizationRequestRepository, "authorizationRequestRepository cannot be null");
			this.authorizationRequestRepository = authorizationRequestRepository;
			return this;
		}

		/**
		 * Sets the client used for requesting the access token credential from the Token
		 * Endpoint.
		 * @param accessTokenResponseClient the client used for requesting the access
		 * token credential from the Token Endpoint
		 * @return the {@link AuthorizationCodeGrantConfigurer} for further configuration
		 */
		public AuthorizationCodeGrantConfigurer accessTokenResponseClient(
				OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient) {

			Assert.notNull(accessTokenResponseClient, "accessTokenResponseClient cannot be null");
			this.accessTokenResponseClient = accessTokenResponseClient;
			return this;
		}

		/**
		 * Returns the {@link OAuth2ClientConfigurer} for further configuration.
		 * @return the {@link OAuth2ClientConfigurer}
		 */
		public OAuth2ClientConfigurer<B> and() {
			return OAuth2ClientConfigurer.this;
		}

		private void init(B builder) {
			OAuth2AuthorizationCodeAuthenticationProvider authorizationCodeAuthenticationProvider = new OAuth2AuthorizationCodeAuthenticationProvider(
					getAccessTokenResponseClient());
			builder.authenticationProvider(postProcess(authorizationCodeAuthenticationProvider));
		}

		private void configure(B builder) {
			OAuth2AuthorizationRequestRedirectFilter authorizationRequestRedirectFilter = createAuthorizationRequestRedirectFilter(
					builder);
			builder.addFilter(postProcess(authorizationRequestRedirectFilter));
			OAuth2AuthorizationCodeGrantFilter authorizationCodeGrantFilter = createAuthorizationCodeGrantFilter(
					builder);
			builder.addFilter(postProcess(authorizationCodeGrantFilter));
		}

		private OAuth2AuthorizationRequestRedirectFilter createAuthorizationRequestRedirectFilter(B builder) {
			OAuth2AuthorizationRequestResolver resolver = getAuthorizationRequestResolver();
			OAuth2AuthorizationRequestRedirectFilter authorizationRequestRedirectFilter = new OAuth2AuthorizationRequestRedirectFilter(
					resolver);

			if (this.authorizationRequestRepository != null) {
				authorizationRequestRedirectFilter
						.setAuthorizationRequestRepository(this.authorizationRequestRepository);
			}
			RequestCache requestCache = builder.getSharedObject(RequestCache.class);
			if (requestCache != null) {
				authorizationRequestRedirectFilter.setRequestCache(requestCache);
			}
			return authorizationRequestRedirectFilter;
		}

		private OAuth2AuthorizationRequestResolver getAuthorizationRequestResolver() {
			if (this.authorizationRequestResolver != null) {
				return this.authorizationRequestResolver;
			}
			ClientRegistrationRepository clientRegistrationRepository = OAuth2ClientConfigurerUtils
					.getClientRegistrationRepository(getBuilder());
			return new DefaultOAuth2AuthorizationRequestResolver(clientRegistrationRepository,
					OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI);
		}

		private OAuth2AuthorizationCodeGrantFilter createAuthorizationCodeGrantFilter(B builder) {
			AuthenticationManager authenticationManager = builder.getSharedObject(AuthenticationManager.class);
			OAuth2AuthorizationCodeGrantFilter authorizationCodeGrantFilter = new OAuth2AuthorizationCodeGrantFilter(
					OAuth2ClientConfigurerUtils.getClientRegistrationRepository(builder),
					OAuth2ClientConfigurerUtils.getAuthorizedClientRepository(builder), authenticationManager);

			if (this.authorizationRequestRepository != null) {
				authorizationCodeGrantFilter.setAuthorizationRequestRepository(this.authorizationRequestRepository);
			}
			RequestCache requestCache = builder.getSharedObject(RequestCache.class);
			if (requestCache != null) {
				authorizationCodeGrantFilter.setRequestCache(requestCache);
			}
			return authorizationCodeGrantFilter;
		}

		private OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> getAccessTokenResponseClient() {
			if (this.accessTokenResponseClient != null) {
				return this.accessTokenResponseClient;
			}
			return new DefaultAuthorizationCodeTokenResponseClient();
		}

	}

}
