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
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationValidator;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2PushedAuthorizationRequestAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2PushedAuthorizationRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.web.OAuth2PushedAuthorizationRequestEndpointFilter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeRequestAuthenticationConverter;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.DelegatingAuthenticationConverter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

/**
 * Configurer for the OAuth 2.0 Pushed Authorization Request Endpoint.
 *
 * @author Joe Grandja
 * @since 7.0
 * @see OAuth2AuthorizationServerConfigurer#pushedAuthorizationRequestEndpoint
 * @see OAuth2PushedAuthorizationRequestEndpointFilter
 */
public final class OAuth2PushedAuthorizationRequestEndpointConfigurer extends AbstractOAuth2Configurer {

	private RequestMatcher requestMatcher;

	private final List<AuthenticationConverter> pushedAuthorizationRequestConverters = new ArrayList<>();

	private Consumer<List<AuthenticationConverter>> pushedAuthorizationRequestConvertersConsumer = (
			authorizationRequestConverters) -> {
	};

	private final List<AuthenticationProvider> authenticationProviders = new ArrayList<>();

	private Consumer<List<AuthenticationProvider>> authenticationProvidersConsumer = (authenticationProviders) -> {
	};

	private AuthenticationSuccessHandler pushedAuthorizationResponseHandler;

	private AuthenticationFailureHandler errorResponseHandler;

	private Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> authorizationCodeRequestAuthenticationValidator;

	/**
	 * Restrict for internal use only.
	 * @param objectPostProcessor an {@code ObjectPostProcessor}
	 */
	OAuth2PushedAuthorizationRequestEndpointConfigurer(ObjectPostProcessor<Object> objectPostProcessor) {
		super(objectPostProcessor);
	}

	/**
	 * Adds an {@link AuthenticationConverter} used when attempting to extract a Pushed
	 * Authorization Request from {@link HttpServletRequest} to an instance of
	 * {@link OAuth2PushedAuthorizationRequestAuthenticationToken} used for authenticating
	 * the request.
	 * @param pushedAuthorizationRequestConverter an {@link AuthenticationConverter} used
	 * when attempting to extract a Pushed Authorization Request from
	 * {@link HttpServletRequest}
	 * @return the {@link OAuth2PushedAuthorizationRequestEndpointConfigurer} for further
	 * configuration
	 */
	public OAuth2PushedAuthorizationRequestEndpointConfigurer pushedAuthorizationRequestConverter(
			AuthenticationConverter pushedAuthorizationRequestConverter) {
		Assert.notNull(pushedAuthorizationRequestConverter, "pushedAuthorizationRequestConverter cannot be null");
		this.pushedAuthorizationRequestConverters.add(pushedAuthorizationRequestConverter);
		return this;
	}

	/**
	 * Sets the {@code Consumer} providing access to the {@code List} of default and
	 * (optionally) added
	 * {@link #pushedAuthorizationRequestConverter(AuthenticationConverter)
	 * AuthenticationConverter}'s allowing the ability to add, remove, or customize a
	 * specific {@link AuthenticationConverter}.
	 * @param pushedAuthorizationRequestConvertersConsumer the {@code Consumer} providing
	 * access to the {@code List} of default and (optionally) added
	 * {@link AuthenticationConverter}'s
	 * @return the {@link OAuth2PushedAuthorizationRequestEndpointConfigurer} for further
	 * configuration
	 */
	public OAuth2PushedAuthorizationRequestEndpointConfigurer pushedAuthorizationRequestConverters(
			Consumer<List<AuthenticationConverter>> pushedAuthorizationRequestConvertersConsumer) {
		Assert.notNull(pushedAuthorizationRequestConvertersConsumer,
				"pushedAuthorizationRequestConvertersConsumer cannot be null");
		this.pushedAuthorizationRequestConvertersConsumer = pushedAuthorizationRequestConvertersConsumer;
		return this;
	}

	/**
	 * Adds an {@link AuthenticationProvider} used for authenticating an
	 * {@link OAuth2PushedAuthorizationRequestAuthenticationToken}.
	 * @param authenticationProvider an {@link AuthenticationProvider} used for
	 * authenticating an {@link OAuth2PushedAuthorizationRequestAuthenticationToken}
	 * @return the {@link OAuth2PushedAuthorizationRequestEndpointConfigurer} for further
	 * configuration
	 */
	public OAuth2PushedAuthorizationRequestEndpointConfigurer authenticationProvider(
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
	 * @return the {@link OAuth2PushedAuthorizationRequestEndpointConfigurer} for further
	 * configuration
	 */
	public OAuth2PushedAuthorizationRequestEndpointConfigurer authenticationProviders(
			Consumer<List<AuthenticationProvider>> authenticationProvidersConsumer) {
		Assert.notNull(authenticationProvidersConsumer, "authenticationProvidersConsumer cannot be null");
		this.authenticationProvidersConsumer = authenticationProvidersConsumer;
		return this;
	}

	/**
	 * Sets the {@link AuthenticationSuccessHandler} used for handling an
	 * {@link OAuth2PushedAuthorizationRequestAuthenticationToken} and returning the
	 * Pushed Authorization Response.
	 * @param pushedAuthorizationResponseHandler the {@link AuthenticationSuccessHandler}
	 * used for handling an {@link OAuth2PushedAuthorizationRequestAuthenticationToken}
	 * @return the {@link OAuth2PushedAuthorizationRequestEndpointConfigurer} for further
	 * configuration
	 */
	public OAuth2PushedAuthorizationRequestEndpointConfigurer pushedAuthorizationResponseHandler(
			AuthenticationSuccessHandler pushedAuthorizationResponseHandler) {
		this.pushedAuthorizationResponseHandler = pushedAuthorizationResponseHandler;
		return this;
	}

	/**
	 * Sets the {@link AuthenticationFailureHandler} used for handling an
	 * {@link OAuth2AuthorizationCodeRequestAuthenticationException} and returning the
	 * {@link OAuth2Error Error Response}.
	 * @param errorResponseHandler the {@link AuthenticationFailureHandler} used for
	 * handling an {@link OAuth2AuthorizationCodeRequestAuthenticationException}
	 * @return the {@link OAuth2PushedAuthorizationRequestEndpointConfigurer} for further
	 * configuration
	 */
	public OAuth2PushedAuthorizationRequestEndpointConfigurer errorResponseHandler(
			AuthenticationFailureHandler errorResponseHandler) {
		this.errorResponseHandler = errorResponseHandler;
		return this;
	}

	void addAuthorizationCodeRequestAuthenticationValidator(
			Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> authenticationValidator) {
		this.authorizationCodeRequestAuthenticationValidator = (this.authorizationCodeRequestAuthenticationValidator == null)
				? authenticationValidator
				: this.authorizationCodeRequestAuthenticationValidator.andThen(authenticationValidator);
	}

	@Override
	void init(HttpSecurity httpSecurity) {
		AuthorizationServerSettings authorizationServerSettings = OAuth2ConfigurerUtils
			.getAuthorizationServerSettings(httpSecurity);
		String pushedAuthorizationRequestEndpointUri = authorizationServerSettings.isMultipleIssuersAllowed()
				? OAuth2ConfigurerUtils
					.withMultipleIssuersPattern(authorizationServerSettings.getPushedAuthorizationRequestEndpoint())
				: authorizationServerSettings.getPushedAuthorizationRequestEndpoint();
		this.requestMatcher = PathPatternRequestMatcher.withDefaults()
			.matcher(HttpMethod.POST, pushedAuthorizationRequestEndpointUri);
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
		String pushedAuthorizationRequestEndpointUri = authorizationServerSettings.isMultipleIssuersAllowed()
				? OAuth2ConfigurerUtils
					.withMultipleIssuersPattern(authorizationServerSettings.getPushedAuthorizationRequestEndpoint())
				: authorizationServerSettings.getPushedAuthorizationRequestEndpoint();
		OAuth2PushedAuthorizationRequestEndpointFilter pushedAuthorizationRequestEndpointFilter = new OAuth2PushedAuthorizationRequestEndpointFilter(
				authenticationManager, pushedAuthorizationRequestEndpointUri);
		List<AuthenticationConverter> authenticationConverters = createDefaultAuthenticationConverters();
		if (!this.pushedAuthorizationRequestConverters.isEmpty()) {
			authenticationConverters.addAll(0, this.pushedAuthorizationRequestConverters);
		}
		this.pushedAuthorizationRequestConvertersConsumer.accept(authenticationConverters);
		pushedAuthorizationRequestEndpointFilter
			.setAuthenticationConverter(new DelegatingAuthenticationConverter(authenticationConverters));
		if (this.pushedAuthorizationResponseHandler != null) {
			pushedAuthorizationRequestEndpointFilter
				.setAuthenticationSuccessHandler(this.pushedAuthorizationResponseHandler);
		}
		if (this.errorResponseHandler != null) {
			pushedAuthorizationRequestEndpointFilter.setAuthenticationFailureHandler(this.errorResponseHandler);
		}
		httpSecurity.addFilterAfter(postProcess(pushedAuthorizationRequestEndpointFilter), AuthorizationFilter.class);
	}

	@Override
	RequestMatcher getRequestMatcher() {
		return this.requestMatcher;
	}

	private static List<AuthenticationConverter> createDefaultAuthenticationConverters() {
		List<AuthenticationConverter> authenticationConverters = new ArrayList<>();

		authenticationConverters.add(new OAuth2AuthorizationCodeRequestAuthenticationConverter());

		return authenticationConverters;
	}

	private List<AuthenticationProvider> createDefaultAuthenticationProviders(HttpSecurity httpSecurity) {
		List<AuthenticationProvider> authenticationProviders = new ArrayList<>();

		OAuth2PushedAuthorizationRequestAuthenticationProvider pushedAuthorizationRequestAuthenticationProvider = new OAuth2PushedAuthorizationRequestAuthenticationProvider(
				OAuth2ConfigurerUtils.getAuthorizationService(httpSecurity));
		if (this.authorizationCodeRequestAuthenticationValidator != null) {
			pushedAuthorizationRequestAuthenticationProvider
				.setAuthenticationValidator(new OAuth2AuthorizationCodeRequestAuthenticationValidator()
					.andThen(this.authorizationCodeRequestAuthenticationValidator));
		}
		authenticationProviders.add(pushedAuthorizationRequestAuthenticationProvider);

		return authenticationProviders;
	}

}
