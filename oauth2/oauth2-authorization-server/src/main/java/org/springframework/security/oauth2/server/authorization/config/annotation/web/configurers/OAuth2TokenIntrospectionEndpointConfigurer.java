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

package org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenIntrospectionAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenIntrospectionAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.web.OAuth2TokenIntrospectionEndpointFilter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2TokenIntrospectionAuthenticationConverter;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.DelegatingAuthenticationConverter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

/**
 * Configurer for the OAuth 2.0 Token Introspection Endpoint.
 *
 * @author Gaurav Tiwari
 * @author Joe Grandja
 * @since 7.0
 * @see OAuth2AuthorizationServerConfigurer#tokenIntrospectionEndpoint(Customizer)
 * @see OAuth2TokenIntrospectionEndpointFilter
 */
public final class OAuth2TokenIntrospectionEndpointConfigurer extends AbstractOAuth2Configurer {

	private RequestMatcher requestMatcher;

	private final List<AuthenticationConverter> introspectionRequestConverters = new ArrayList<>();

	private Consumer<List<AuthenticationConverter>> introspectionRequestConvertersConsumer = (
			introspectionRequestConverters) -> {
	};

	private final List<AuthenticationProvider> authenticationProviders = new ArrayList<>();

	private Consumer<List<AuthenticationProvider>> authenticationProvidersConsumer = (authenticationProviders) -> {
	};

	private AuthenticationSuccessHandler introspectionResponseHandler;

	private AuthenticationFailureHandler errorResponseHandler;

	/**
	 * Restrict for internal use only.
	 * @param objectPostProcessor an {@code ObjectPostProcessor}
	 */
	OAuth2TokenIntrospectionEndpointConfigurer(ObjectPostProcessor<Object> objectPostProcessor) {
		super(objectPostProcessor);
	}

	/**
	 * Adds an {@link AuthenticationConverter} used when attempting to extract an
	 * Introspection Request from {@link HttpServletRequest} to an instance of
	 * {@link OAuth2TokenIntrospectionAuthenticationToken} used for authenticating the
	 * request.
	 * @param introspectionRequestConverter an {@link AuthenticationConverter} used when
	 * attempting to extract an Introspection Request from {@link HttpServletRequest}
	 * @return the {@link OAuth2TokenIntrospectionEndpointConfigurer} for further
	 * configuration
	 */
	public OAuth2TokenIntrospectionEndpointConfigurer introspectionRequestConverter(
			AuthenticationConverter introspectionRequestConverter) {
		Assert.notNull(introspectionRequestConverter, "introspectionRequestConverter cannot be null");
		this.introspectionRequestConverters.add(introspectionRequestConverter);
		return this;
	}

	/**
	 * Sets the {@code Consumer} providing access to the {@code List} of default and
	 * (optionally) added {@link #introspectionRequestConverter(AuthenticationConverter)
	 * AuthenticationConverter}'s allowing the ability to add, remove, or customize a
	 * specific {@link AuthenticationConverter}.
	 * @param introspectionRequestConvertersConsumer the {@code Consumer} providing access
	 * to the {@code List} of default and (optionally) added
	 * {@link AuthenticationConverter}'s
	 * @return the {@link OAuth2TokenIntrospectionEndpointConfigurer} for further
	 * configuration
	 */
	public OAuth2TokenIntrospectionEndpointConfigurer introspectionRequestConverters(
			Consumer<List<AuthenticationConverter>> introspectionRequestConvertersConsumer) {
		Assert.notNull(introspectionRequestConvertersConsumer, "introspectionRequestConvertersConsumer cannot be null");
		this.introspectionRequestConvertersConsumer = introspectionRequestConvertersConsumer;
		return this;
	}

	/**
	 * Adds an {@link AuthenticationProvider} used for authenticating a type of
	 * {@link OAuth2TokenIntrospectionAuthenticationToken}.
	 * @param authenticationProvider an {@link AuthenticationProvider} used for
	 * authenticating a type of {@link OAuth2TokenIntrospectionAuthenticationToken}
	 * @return the {@link OAuth2TokenIntrospectionEndpointConfigurer} for further
	 * configuration
	 */
	public OAuth2TokenIntrospectionEndpointConfigurer authenticationProvider(
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
	 * @return the {@link OAuth2TokenIntrospectionEndpointConfigurer} for further
	 * configuration
	 */
	public OAuth2TokenIntrospectionEndpointConfigurer authenticationProviders(
			Consumer<List<AuthenticationProvider>> authenticationProvidersConsumer) {
		Assert.notNull(authenticationProvidersConsumer, "authenticationProvidersConsumer cannot be null");
		this.authenticationProvidersConsumer = authenticationProvidersConsumer;
		return this;
	}

	/**
	 * Sets the {@link AuthenticationSuccessHandler} used for handling an
	 * {@link OAuth2TokenIntrospectionAuthenticationToken}.
	 * @param introspectionResponseHandler the {@link AuthenticationSuccessHandler} used
	 * for handling an {@link OAuth2TokenIntrospectionAuthenticationToken}
	 * @return the {@link OAuth2TokenIntrospectionEndpointConfigurer} for further
	 * configuration
	 */
	public OAuth2TokenIntrospectionEndpointConfigurer introspectionResponseHandler(
			AuthenticationSuccessHandler introspectionResponseHandler) {
		this.introspectionResponseHandler = introspectionResponseHandler;
		return this;
	}

	/**
	 * Sets the {@link AuthenticationFailureHandler} used for handling an
	 * {@link OAuth2AuthenticationException} and returning the {@link OAuth2Error Error
	 * Response}.
	 * @param errorResponseHandler the {@link AuthenticationFailureHandler} used for
	 * handling an {@link OAuth2AuthenticationException}
	 * @return the {@link OAuth2TokenIntrospectionEndpointConfigurer} for further
	 * configuration
	 */
	public OAuth2TokenIntrospectionEndpointConfigurer errorResponseHandler(
			AuthenticationFailureHandler errorResponseHandler) {
		this.errorResponseHandler = errorResponseHandler;
		return this;
	}

	@Override
	void init(HttpSecurity httpSecurity) {
		AuthorizationServerSettings authorizationServerSettings = OAuth2ConfigurerUtils
			.getAuthorizationServerSettings(httpSecurity);
		String tokenIntrospectionEndpointUri = authorizationServerSettings.isMultipleIssuersAllowed()
				? OAuth2ConfigurerUtils
					.withMultipleIssuersPattern(authorizationServerSettings.getTokenIntrospectionEndpoint())
				: authorizationServerSettings.getTokenIntrospectionEndpoint();
		this.requestMatcher = PathPatternRequestMatcher.withDefaults()
			.matcher(HttpMethod.POST, tokenIntrospectionEndpointUri);

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
		String tokenIntrospectionEndpointUri = authorizationServerSettings.isMultipleIssuersAllowed()
				? OAuth2ConfigurerUtils
					.withMultipleIssuersPattern(authorizationServerSettings.getTokenIntrospectionEndpoint())
				: authorizationServerSettings.getTokenIntrospectionEndpoint();
		OAuth2TokenIntrospectionEndpointFilter introspectionEndpointFilter = new OAuth2TokenIntrospectionEndpointFilter(
				authenticationManager, tokenIntrospectionEndpointUri);
		List<AuthenticationConverter> authenticationConverters = createDefaultAuthenticationConverters();
		if (!this.introspectionRequestConverters.isEmpty()) {
			authenticationConverters.addAll(0, this.introspectionRequestConverters);
		}
		this.introspectionRequestConvertersConsumer.accept(authenticationConverters);
		introspectionEndpointFilter
			.setAuthenticationConverter(new DelegatingAuthenticationConverter(authenticationConverters));
		if (this.introspectionResponseHandler != null) {
			introspectionEndpointFilter.setAuthenticationSuccessHandler(this.introspectionResponseHandler);
		}
		if (this.errorResponseHandler != null) {
			introspectionEndpointFilter.setAuthenticationFailureHandler(this.errorResponseHandler);
		}
		httpSecurity.addFilterAfter(postProcess(introspectionEndpointFilter), AuthorizationFilter.class);
	}

	@Override
	RequestMatcher getRequestMatcher() {
		return this.requestMatcher;
	}

	private static List<AuthenticationConverter> createDefaultAuthenticationConverters() {
		List<AuthenticationConverter> authenticationConverters = new ArrayList<>();

		authenticationConverters.add(new OAuth2TokenIntrospectionAuthenticationConverter());

		return authenticationConverters;
	}

	private static List<AuthenticationProvider> createDefaultAuthenticationProviders(HttpSecurity httpSecurity) {
		List<AuthenticationProvider> authenticationProviders = new ArrayList<>();

		OAuth2TokenIntrospectionAuthenticationProvider tokenIntrospectionAuthenticationProvider = new OAuth2TokenIntrospectionAuthenticationProvider(
				OAuth2ConfigurerUtils.getRegisteredClientRepository(httpSecurity),
				OAuth2ConfigurerUtils.getAuthorizationService(httpSecurity));
		authenticationProviders.add(tokenIntrospectionAuthenticationProvider);

		return authenticationProviders;
	}

}
