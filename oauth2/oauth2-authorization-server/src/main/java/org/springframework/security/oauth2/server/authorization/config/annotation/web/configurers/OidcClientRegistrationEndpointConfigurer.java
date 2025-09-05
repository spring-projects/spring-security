/*
 * Copyright 2020-2025 the original author or authors.
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
package org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.authorization.oidc.OidcClientRegistration;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcClientConfigurationAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcClientRegistrationAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcClientRegistrationAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.oidc.web.OidcClientRegistrationEndpointFilter;
import org.springframework.security.oauth2.server.authorization.oidc.web.authentication.OidcClientRegistrationAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.DelegatingAuthenticationConverter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

/**
 * Configurer for OpenID Connect 1.0 Dynamic Client Registration Endpoint.
 *
 * @author Joe Grandja
 * @author Daniel Garnier-Moiroux
 * @since 0.2.0
 * @see OidcConfigurer#clientRegistrationEndpoint
 * @see OidcClientRegistrationEndpointFilter
 */
public final class OidcClientRegistrationEndpointConfigurer extends AbstractOAuth2Configurer {

	private RequestMatcher requestMatcher;

	private final List<AuthenticationConverter> clientRegistrationRequestConverters = new ArrayList<>();

	private Consumer<List<AuthenticationConverter>> clientRegistrationRequestConvertersConsumer = (
			clientRegistrationRequestConverters) -> {
	};

	private final List<AuthenticationProvider> authenticationProviders = new ArrayList<>();

	private Consumer<List<AuthenticationProvider>> authenticationProvidersConsumer = (authenticationProviders) -> {
	};

	private AuthenticationSuccessHandler clientRegistrationResponseHandler;

	private AuthenticationFailureHandler errorResponseHandler;

	/**
	 * Restrict for internal use only.
	 * @param objectPostProcessor an {@code ObjectPostProcessor}
	 */
	OidcClientRegistrationEndpointConfigurer(ObjectPostProcessor<Object> objectPostProcessor) {
		super(objectPostProcessor);
	}

	/**
	 * Adds an {@link AuthenticationConverter} used when attempting to extract a Client
	 * Registration Request from {@link HttpServletRequest} to an instance of
	 * {@link OidcClientRegistrationAuthenticationToken} used for authenticating the
	 * request.
	 * @param clientRegistrationRequestConverter an {@link AuthenticationConverter} used
	 * when attempting to extract a Client Registration Request from
	 * {@link HttpServletRequest}
	 * @return the {@link OidcClientRegistrationEndpointConfigurer} for further
	 * configuration
	 * @since 0.4.0
	 */
	public OidcClientRegistrationEndpointConfigurer clientRegistrationRequestConverter(
			AuthenticationConverter clientRegistrationRequestConverter) {
		Assert.notNull(clientRegistrationRequestConverter, "clientRegistrationRequestConverter cannot be null");
		this.clientRegistrationRequestConverters.add(clientRegistrationRequestConverter);
		return this;
	}

	/**
	 * Sets the {@code Consumer} providing access to the {@code List} of default and
	 * (optionally) added
	 * {@link #clientRegistrationRequestConverter(AuthenticationConverter)
	 * AuthenticationConverter}'s allowing the ability to add, remove, or customize a
	 * specific {@link AuthenticationConverter}.
	 * @param clientRegistrationRequestConvertersConsumer the {@code Consumer} providing
	 * access to the {@code List} of default and (optionally) added
	 * {@link AuthenticationConverter}'s
	 * @return the {@link OidcUserInfoEndpointConfigurer} for further configuration
	 * @since 0.4.0
	 */
	public OidcClientRegistrationEndpointConfigurer clientRegistrationRequestConverters(
			Consumer<List<AuthenticationConverter>> clientRegistrationRequestConvertersConsumer) {
		Assert.notNull(clientRegistrationRequestConvertersConsumer,
				"clientRegistrationRequestConvertersConsumer cannot be null");
		this.clientRegistrationRequestConvertersConsumer = clientRegistrationRequestConvertersConsumer;
		return this;
	}

	/**
	 * Adds an {@link AuthenticationProvider} used for authenticating an
	 * {@link OidcClientRegistrationAuthenticationToken}.
	 * @param authenticationProvider an {@link AuthenticationProvider} used for
	 * authenticating an {@link OidcClientRegistrationAuthenticationToken}
	 * @return the {@link OidcClientRegistrationEndpointConfigurer} for further
	 * configuration
	 * @since 0.4.0
	 */
	public OidcClientRegistrationEndpointConfigurer authenticationProvider(
			AuthenticationProvider authenticationProvider) {
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
	 * @return the {@link OidcClientRegistrationEndpointConfigurer} for further
	 * configuration
	 * @since 0.4.0
	 */
	public OidcClientRegistrationEndpointConfigurer authenticationProviders(
			Consumer<List<AuthenticationProvider>> authenticationProvidersConsumer) {
		Assert.notNull(authenticationProvidersConsumer, "authenticationProvidersConsumer cannot be null");
		this.authenticationProvidersConsumer = authenticationProvidersConsumer;
		return this;
	}

	/**
	 * Sets the {@link AuthenticationSuccessHandler} used for handling an
	 * {@link OidcClientRegistrationAuthenticationToken} and returning the
	 * {@link OidcClientRegistration Client Registration Response}.
	 * @param clientRegistrationResponseHandler the {@link AuthenticationSuccessHandler}
	 * used for handling an {@link OidcClientRegistrationAuthenticationToken}
	 * @return the {@link OidcClientRegistrationEndpointConfigurer} for further
	 * configuration
	 * @since 0.4.0
	 */
	public OidcClientRegistrationEndpointConfigurer clientRegistrationResponseHandler(
			AuthenticationSuccessHandler clientRegistrationResponseHandler) {
		this.clientRegistrationResponseHandler = clientRegistrationResponseHandler;
		return this;
	}

	/**
	 * Sets the {@link AuthenticationFailureHandler} used for handling an
	 * {@link OAuth2AuthenticationException} and returning the {@link OAuth2Error Error
	 * Response}.
	 * @param errorResponseHandler the {@link AuthenticationFailureHandler} used for
	 * handling an {@link OAuth2AuthenticationException}
	 * @return the {@link OidcClientRegistrationEndpointConfigurer} for further
	 * configuration
	 * @since 0.4.0
	 */
	public OidcClientRegistrationEndpointConfigurer errorResponseHandler(
			AuthenticationFailureHandler errorResponseHandler) {
		this.errorResponseHandler = errorResponseHandler;
		return this;
	}

	@Override
	void init(HttpSecurity httpSecurity) {
		AuthorizationServerSettings authorizationServerSettings = OAuth2ConfigurerUtils
			.getAuthorizationServerSettings(httpSecurity);
		String clientRegistrationEndpointUri = authorizationServerSettings.isMultipleIssuersAllowed()
				? OAuth2ConfigurerUtils
					.withMultipleIssuersPattern(authorizationServerSettings.getOidcClientRegistrationEndpoint())
				: authorizationServerSettings.getOidcClientRegistrationEndpoint();
		this.requestMatcher = new OrRequestMatcher(
				PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, clientRegistrationEndpointUri),
				PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.GET, clientRegistrationEndpointUri));

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

		String clientRegistrationEndpointUri = authorizationServerSettings.isMultipleIssuersAllowed()
				? OAuth2ConfigurerUtils
					.withMultipleIssuersPattern(authorizationServerSettings.getOidcClientRegistrationEndpoint())
				: authorizationServerSettings.getOidcClientRegistrationEndpoint();
		OidcClientRegistrationEndpointFilter oidcClientRegistrationEndpointFilter = new OidcClientRegistrationEndpointFilter(
				authenticationManager, clientRegistrationEndpointUri);
		List<AuthenticationConverter> authenticationConverters = createDefaultAuthenticationConverters();
		if (!this.clientRegistrationRequestConverters.isEmpty()) {
			authenticationConverters.addAll(0, this.clientRegistrationRequestConverters);
		}
		this.clientRegistrationRequestConvertersConsumer.accept(authenticationConverters);
		oidcClientRegistrationEndpointFilter
			.setAuthenticationConverter(new DelegatingAuthenticationConverter(authenticationConverters));
		if (this.clientRegistrationResponseHandler != null) {
			oidcClientRegistrationEndpointFilter
				.setAuthenticationSuccessHandler(this.clientRegistrationResponseHandler);
		}
		if (this.errorResponseHandler != null) {
			oidcClientRegistrationEndpointFilter.setAuthenticationFailureHandler(this.errorResponseHandler);
		}
		httpSecurity.addFilterAfter(postProcess(oidcClientRegistrationEndpointFilter), AuthorizationFilter.class);
	}

	@Override
	RequestMatcher getRequestMatcher() {
		return this.requestMatcher;
	}

	private static List<AuthenticationConverter> createDefaultAuthenticationConverters() {
		List<AuthenticationConverter> authenticationConverters = new ArrayList<>();

		authenticationConverters.add(new OidcClientRegistrationAuthenticationConverter());

		return authenticationConverters;
	}

	private static List<AuthenticationProvider> createDefaultAuthenticationProviders(HttpSecurity httpSecurity) {
		List<AuthenticationProvider> authenticationProviders = new ArrayList<>();

		OidcClientRegistrationAuthenticationProvider oidcClientRegistrationAuthenticationProvider = new OidcClientRegistrationAuthenticationProvider(
				OAuth2ConfigurerUtils.getRegisteredClientRepository(httpSecurity),
				OAuth2ConfigurerUtils.getAuthorizationService(httpSecurity),
				OAuth2ConfigurerUtils.getTokenGenerator(httpSecurity));
		PasswordEncoder passwordEncoder = OAuth2ConfigurerUtils.getOptionalBean(httpSecurity, PasswordEncoder.class);
		if (passwordEncoder != null) {
			oidcClientRegistrationAuthenticationProvider.setPasswordEncoder(passwordEncoder);
		}
		authenticationProviders.add(oidcClientRegistrationAuthenticationProvider);

		OidcClientConfigurationAuthenticationProvider oidcClientConfigurationAuthenticationProvider = new OidcClientConfigurationAuthenticationProvider(
				OAuth2ConfigurerUtils.getRegisteredClientRepository(httpSecurity),
				OAuth2ConfigurerUtils.getAuthorizationService(httpSecurity));
		authenticationProviders.add(oidcClientConfigurationAuthenticationProvider);

		return authenticationProviders;
	}

}
