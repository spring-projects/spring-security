/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2DeviceCodeAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.web.OAuth2TokenEndpointFilter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2ClientCredentialsAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2DeviceCodeAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2RefreshTokenAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2TokenExchangeAuthenticationConverter;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.DelegatingAuthenticationConverter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

/**
 * Configurer for the OAuth 2.0 Token Endpoint.
 *
 * @author Joe Grandja
 * @since 7.0
 * @see OAuth2AuthorizationServerConfigurer#tokenEndpoint
 * @see OAuth2TokenEndpointFilter
 */
public final class OAuth2TokenEndpointConfigurer extends AbstractOAuth2Configurer {

	private RequestMatcher requestMatcher;

	private final List<AuthenticationConverter> accessTokenRequestConverters = new ArrayList<>();

	private Consumer<List<AuthenticationConverter>> accessTokenRequestConvertersConsumer = (
			accessTokenRequestConverters) -> {
	};

	private final List<AuthenticationProvider> authenticationProviders = new ArrayList<>();

	private Consumer<List<AuthenticationProvider>> authenticationProvidersConsumer = (authenticationProviders) -> {
	};

	private AuthenticationSuccessHandler accessTokenResponseHandler;

	private AuthenticationFailureHandler errorResponseHandler;

	/**
	 * Restrict for internal use only.
	 * @param objectPostProcessor an {@code ObjectPostProcessor}
	 */
	OAuth2TokenEndpointConfigurer(ObjectPostProcessor<Object> objectPostProcessor) {
		super(objectPostProcessor);
	}

	/**
	 * Adds an {@link AuthenticationConverter} used when attempting to extract an Access
	 * Token Request from {@link HttpServletRequest} to an instance of
	 * {@link OAuth2AuthorizationGrantAuthenticationToken} used for authenticating the
	 * authorization grant.
	 * @param accessTokenRequestConverter an {@link AuthenticationConverter} used when
	 * attempting to extract an Access Token Request from {@link HttpServletRequest}
	 * @return the {@link OAuth2TokenEndpointConfigurer} for further configuration
	 */
	public OAuth2TokenEndpointConfigurer accessTokenRequestConverter(
			AuthenticationConverter accessTokenRequestConverter) {
		Assert.notNull(accessTokenRequestConverter, "accessTokenRequestConverter cannot be null");
		this.accessTokenRequestConverters.add(accessTokenRequestConverter);
		return this;
	}

	/**
	 * Sets the {@code Consumer} providing access to the {@code List} of default and
	 * (optionally) added {@link #accessTokenRequestConverter(AuthenticationConverter)
	 * AuthenticationConverter}'s allowing the ability to add, remove, or customize a
	 * specific {@link AuthenticationConverter}.
	 * @param accessTokenRequestConvertersConsumer the {@code Consumer} providing access
	 * to the {@code List} of default and (optionally) added
	 * {@link AuthenticationConverter}'s
	 * @return the {@link OAuth2TokenEndpointConfigurer} for further configuration
	 */
	public OAuth2TokenEndpointConfigurer accessTokenRequestConverters(
			Consumer<List<AuthenticationConverter>> accessTokenRequestConvertersConsumer) {
		Assert.notNull(accessTokenRequestConvertersConsumer, "accessTokenRequestConvertersConsumer cannot be null");
		this.accessTokenRequestConvertersConsumer = accessTokenRequestConvertersConsumer;
		return this;
	}

	/**
	 * Adds an {@link AuthenticationProvider} used for authenticating a type of
	 * {@link OAuth2AuthorizationGrantAuthenticationToken}.
	 * @param authenticationProvider an {@link AuthenticationProvider} used for
	 * authenticating a type of {@link OAuth2AuthorizationGrantAuthenticationToken}
	 * @return the {@link OAuth2TokenEndpointConfigurer} for further configuration
	 */
	public OAuth2TokenEndpointConfigurer authenticationProvider(AuthenticationProvider authenticationProvider) {
		Assert.notNull(authenticationProvider, "authenticationProvider cannot be null");
		this.authenticationProviders.add(authenticationProvider);
		return this;
	}

	/**
	 * Sets the {@code Consumer} providing access to the {@code List} of default and
	 * (optionally) added {@link #authenticationProvider(AuthenticationProvider)
	 * AuthenticationProvider}'s allowing the ability to add, remove, or customize a
	 * specific {@link AuthenticationProvider}.
	 * @param authenticationProvidersConsumer the {@code Consumer} providing access to the
	 * {@code List} of default and (optionally) added {@link AuthenticationProvider}'s
	 * @return the {@link OAuth2TokenEndpointConfigurer} for further configuration
	 */
	public OAuth2TokenEndpointConfigurer authenticationProviders(
			Consumer<List<AuthenticationProvider>> authenticationProvidersConsumer) {
		Assert.notNull(authenticationProvidersConsumer, "authenticationProvidersConsumer cannot be null");
		this.authenticationProvidersConsumer = authenticationProvidersConsumer;
		return this;
	}

	/**
	 * Sets the {@link AuthenticationSuccessHandler} used for handling an
	 * {@link OAuth2AccessTokenAuthenticationToken} and returning the
	 * {@link OAuth2AccessTokenResponse Access Token Response}.
	 * @param accessTokenResponseHandler the {@link AuthenticationSuccessHandler} used for
	 * handling an {@link OAuth2AccessTokenAuthenticationToken}
	 * @return the {@link OAuth2TokenEndpointConfigurer} for further configuration
	 */
	public OAuth2TokenEndpointConfigurer accessTokenResponseHandler(
			AuthenticationSuccessHandler accessTokenResponseHandler) {
		this.accessTokenResponseHandler = accessTokenResponseHandler;
		return this;
	}

	/**
	 * Sets the {@link AuthenticationFailureHandler} used for handling an
	 * {@link OAuth2AuthenticationException} and returning the {@link OAuth2Error Error
	 * Response}.
	 * @param errorResponseHandler the {@link AuthenticationFailureHandler} used for
	 * handling an {@link OAuth2AuthenticationException}
	 * @return the {@link OAuth2TokenEndpointConfigurer} for further configuration
	 */
	public OAuth2TokenEndpointConfigurer errorResponseHandler(AuthenticationFailureHandler errorResponseHandler) {
		this.errorResponseHandler = errorResponseHandler;
		return this;
	}

	@Override
	void init(HttpSecurity httpSecurity) {
		AuthorizationServerSettings authorizationServerSettings = OAuth2ConfigurerUtils
			.getAuthorizationServerSettings(httpSecurity);
		String tokenEndpointUri = authorizationServerSettings.isMultipleIssuersAllowed()
				? OAuth2ConfigurerUtils.withMultipleIssuersPattern(authorizationServerSettings.getTokenEndpoint())
				: authorizationServerSettings.getTokenEndpoint();
		this.requestMatcher = PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, tokenEndpointUri);

		List<AuthenticationProvider> authenticationProviders = createDefaultAuthenticationProviders(httpSecurity);
		if (!this.authenticationProviders.isEmpty()) {
			authenticationProviders.addAll(0, this.authenticationProviders);
		}
		this.authenticationProvidersConsumer.accept(authenticationProviders);
		authenticationProviders.forEach(
				(authenticationProvider) -> httpSecurity.authenticationProvider(postProcess(authenticationProvider)));
	}

	@Override
	void configure(HttpSecurity httpSecurity) {
		AuthenticationManager authenticationManager = httpSecurity.getSharedObject(AuthenticationManager.class);
		AuthorizationServerSettings authorizationServerSettings = OAuth2ConfigurerUtils
			.getAuthorizationServerSettings(httpSecurity);

		String tokenEndpointUri = authorizationServerSettings.isMultipleIssuersAllowed()
				? OAuth2ConfigurerUtils.withMultipleIssuersPattern(authorizationServerSettings.getTokenEndpoint())
				: authorizationServerSettings.getTokenEndpoint();
		OAuth2TokenEndpointFilter tokenEndpointFilter = new OAuth2TokenEndpointFilter(authenticationManager,
				tokenEndpointUri);
		List<AuthenticationConverter> authenticationConverters = createDefaultAuthenticationConverters();
		if (!this.accessTokenRequestConverters.isEmpty()) {
			authenticationConverters.addAll(0, this.accessTokenRequestConverters);
		}
		this.accessTokenRequestConvertersConsumer.accept(authenticationConverters);
		tokenEndpointFilter.setAuthenticationConverter(new DelegatingAuthenticationConverter(authenticationConverters));
		if (this.accessTokenResponseHandler != null) {
			tokenEndpointFilter.setAuthenticationSuccessHandler(this.accessTokenResponseHandler);
		}
		if (this.errorResponseHandler != null) {
			tokenEndpointFilter.setAuthenticationFailureHandler(this.errorResponseHandler);
		}
		httpSecurity.addFilterAfter(postProcess(tokenEndpointFilter), AuthorizationFilter.class);
	}

	@Override
	RequestMatcher getRequestMatcher() {
		return this.requestMatcher;
	}

	private static List<AuthenticationConverter> createDefaultAuthenticationConverters() {
		List<AuthenticationConverter> authenticationConverters = new ArrayList<>();

		authenticationConverters.add(new OAuth2AuthorizationCodeAuthenticationConverter());
		authenticationConverters.add(new OAuth2RefreshTokenAuthenticationConverter());
		authenticationConverters.add(new OAuth2ClientCredentialsAuthenticationConverter());
		authenticationConverters.add(new OAuth2DeviceCodeAuthenticationConverter());
		authenticationConverters.add(new OAuth2TokenExchangeAuthenticationConverter());

		return authenticationConverters;
	}

	private static List<AuthenticationProvider> createDefaultAuthenticationProviders(HttpSecurity httpSecurity) {
		List<AuthenticationProvider> authenticationProviders = new ArrayList<>();

		OAuth2AuthorizationService authorizationService = OAuth2ConfigurerUtils.getAuthorizationService(httpSecurity);
		OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator = OAuth2ConfigurerUtils
			.getTokenGenerator(httpSecurity);

		OAuth2AuthorizationCodeAuthenticationProvider authorizationCodeAuthenticationProvider = new OAuth2AuthorizationCodeAuthenticationProvider(
				authorizationService, tokenGenerator);
		SessionRegistry sessionRegistry = httpSecurity.getSharedObject(SessionRegistry.class);
		if (sessionRegistry != null) {
			authorizationCodeAuthenticationProvider.setSessionRegistry(sessionRegistry);
		}
		authenticationProviders.add(authorizationCodeAuthenticationProvider);

		OAuth2RefreshTokenAuthenticationProvider refreshTokenAuthenticationProvider = new OAuth2RefreshTokenAuthenticationProvider(
				authorizationService, tokenGenerator);
		authenticationProviders.add(refreshTokenAuthenticationProvider);

		OAuth2ClientCredentialsAuthenticationProvider clientCredentialsAuthenticationProvider = new OAuth2ClientCredentialsAuthenticationProvider(
				authorizationService, tokenGenerator);
		authenticationProviders.add(clientCredentialsAuthenticationProvider);

		OAuth2DeviceCodeAuthenticationProvider deviceCodeAuthenticationProvider = new OAuth2DeviceCodeAuthenticationProvider(
				authorizationService, tokenGenerator);
		authenticationProviders.add(deviceCodeAuthenticationProvider);

		OAuth2TokenExchangeAuthenticationProvider tokenExchangeAuthenticationProvider = new OAuth2TokenExchangeAuthenticationProvider(
				authorizationService, tokenGenerator);
		authenticationProviders.add(tokenExchangeAuthenticationProvider);

		return authenticationProviders;
	}

}
