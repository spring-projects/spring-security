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
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcLogoutAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcLogoutAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.oidc.web.OidcLogoutEndpointFilter;
import org.springframework.security.oauth2.server.authorization.oidc.web.authentication.OidcLogoutAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.DelegatingAuthenticationConverter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

/**
 * Configurer for OpenID Connect 1.0 RP-Initiated Logout Endpoint.
 *
 * @author Joe Grandja
 * @since 7.0
 * @see OidcConfigurer#logoutEndpoint
 * @see OidcLogoutEndpointFilter
 */
public final class OidcLogoutEndpointConfigurer extends AbstractOAuth2Configurer {

	private RequestMatcher requestMatcher;

	private final List<AuthenticationConverter> logoutRequestConverters = new ArrayList<>();

	private Consumer<List<AuthenticationConverter>> logoutRequestConvertersConsumer = (logoutRequestConverters) -> {
	};

	private final List<AuthenticationProvider> authenticationProviders = new ArrayList<>();

	private Consumer<List<AuthenticationProvider>> authenticationProvidersConsumer = (authenticationProviders) -> {
	};

	private AuthenticationSuccessHandler logoutResponseHandler;

	private AuthenticationFailureHandler errorResponseHandler;

	/**
	 * Restrict for internal use only.
	 * @param objectPostProcessor an {@code ObjectPostProcessor}
	 */
	OidcLogoutEndpointConfigurer(ObjectPostProcessor<Object> objectPostProcessor) {
		super(objectPostProcessor);
	}

	/**
	 * Adds an {@link AuthenticationConverter} used when attempting to extract a Logout
	 * Request from {@link HttpServletRequest} to an instance of
	 * {@link OidcLogoutAuthenticationToken} used for authenticating the request.
	 * @param logoutRequestConverter an {@link AuthenticationConverter} used when
	 * attempting to extract a Logout Request from {@link HttpServletRequest}
	 * @return the {@link OidcLogoutEndpointConfigurer} for further configuration
	 */
	public OidcLogoutEndpointConfigurer logoutRequestConverter(AuthenticationConverter logoutRequestConverter) {
		Assert.notNull(logoutRequestConverter, "logoutRequestConverter cannot be null");
		this.logoutRequestConverters.add(logoutRequestConverter);
		return this;
	}

	/**
	 * Sets the {@code Consumer} providing access to the {@code List} of default and
	 * (optionally) added {@link #logoutRequestConverter(AuthenticationConverter)
	 * AuthenticationConverter}'s allowing the ability to add, remove, or customize a
	 * specific {@link AuthenticationConverter}.
	 * @param logoutRequestConvertersConsumer the {@code Consumer} providing access to the
	 * {@code List} of default and (optionally) added {@link AuthenticationConverter}'s
	 * @return the {@link OidcLogoutEndpointConfigurer} for further configuration
	 */
	public OidcLogoutEndpointConfigurer logoutRequestConverters(
			Consumer<List<AuthenticationConverter>> logoutRequestConvertersConsumer) {
		Assert.notNull(logoutRequestConvertersConsumer, "logoutRequestConvertersConsumer cannot be null");
		this.logoutRequestConvertersConsumer = logoutRequestConvertersConsumer;
		return this;
	}

	/**
	 * Adds an {@link AuthenticationProvider} used for authenticating an
	 * {@link OidcLogoutAuthenticationToken}.
	 * @param authenticationProvider an {@link AuthenticationProvider} used for
	 * authenticating an {@link OidcLogoutAuthenticationToken}
	 * @return the {@link OidcLogoutEndpointConfigurer} for further configuration
	 */
	public OidcLogoutEndpointConfigurer authenticationProvider(AuthenticationProvider authenticationProvider) {
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
	 * @return the {@link OidcLogoutEndpointConfigurer} for further configuration
	 */
	public OidcLogoutEndpointConfigurer authenticationProviders(
			Consumer<List<AuthenticationProvider>> authenticationProvidersConsumer) {
		Assert.notNull(authenticationProvidersConsumer, "authenticationProvidersConsumer cannot be null");
		this.authenticationProvidersConsumer = authenticationProvidersConsumer;
		return this;
	}

	/**
	 * Sets the {@link AuthenticationSuccessHandler} used for handling an
	 * {@link OidcLogoutAuthenticationToken} and performing the logout.
	 * @param logoutResponseHandler the {@link AuthenticationSuccessHandler} used for
	 * handling an {@link OidcLogoutAuthenticationToken}
	 * @return the {@link OidcLogoutEndpointConfigurer} for further configuration
	 */
	public OidcLogoutEndpointConfigurer logoutResponseHandler(AuthenticationSuccessHandler logoutResponseHandler) {
		this.logoutResponseHandler = logoutResponseHandler;
		return this;
	}

	/**
	 * Sets the {@link AuthenticationFailureHandler} used for handling an
	 * {@link OAuth2AuthenticationException} and returning the {@link OAuth2Error Error
	 * Response}.
	 * @param errorResponseHandler the {@link AuthenticationFailureHandler} used for
	 * handling an {@link OAuth2AuthenticationException}
	 * @return the {@link OidcLogoutEndpointConfigurer} for further configuration
	 */
	public OidcLogoutEndpointConfigurer errorResponseHandler(AuthenticationFailureHandler errorResponseHandler) {
		this.errorResponseHandler = errorResponseHandler;
		return this;
	}

	@Override
	void init(HttpSecurity httpSecurity) {
		AuthorizationServerSettings authorizationServerSettings = OAuth2ConfigurerUtils
			.getAuthorizationServerSettings(httpSecurity);
		String logoutEndpointUri = authorizationServerSettings.isMultipleIssuersAllowed()
				? OAuth2ConfigurerUtils.withMultipleIssuersPattern(authorizationServerSettings.getOidcLogoutEndpoint())
				: authorizationServerSettings.getOidcLogoutEndpoint();
		this.requestMatcher = new OrRequestMatcher(
				PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.GET, logoutEndpointUri),
				PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, logoutEndpointUri));

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

		String logoutEndpointUri = authorizationServerSettings.isMultipleIssuersAllowed()
				? OAuth2ConfigurerUtils.withMultipleIssuersPattern(authorizationServerSettings.getOidcLogoutEndpoint())
				: authorizationServerSettings.getOidcLogoutEndpoint();
		OidcLogoutEndpointFilter oidcLogoutEndpointFilter = new OidcLogoutEndpointFilter(authenticationManager,
				logoutEndpointUri);
		List<AuthenticationConverter> authenticationConverters = createDefaultAuthenticationConverters();
		if (!this.logoutRequestConverters.isEmpty()) {
			authenticationConverters.addAll(0, this.logoutRequestConverters);
		}
		this.logoutRequestConvertersConsumer.accept(authenticationConverters);
		oidcLogoutEndpointFilter
			.setAuthenticationConverter(new DelegatingAuthenticationConverter(authenticationConverters));
		if (this.logoutResponseHandler != null) {
			oidcLogoutEndpointFilter.setAuthenticationSuccessHandler(this.logoutResponseHandler);
		}
		if (this.errorResponseHandler != null) {
			oidcLogoutEndpointFilter.setAuthenticationFailureHandler(this.errorResponseHandler);
		}
		httpSecurity.addFilterBefore(postProcess(oidcLogoutEndpointFilter), LogoutFilter.class);
	}

	@Override
	RequestMatcher getRequestMatcher() {
		return this.requestMatcher;
	}

	private static List<AuthenticationConverter> createDefaultAuthenticationConverters() {
		List<AuthenticationConverter> authenticationConverters = new ArrayList<>();

		authenticationConverters.add(new OidcLogoutAuthenticationConverter());

		return authenticationConverters;
	}

	private static List<AuthenticationProvider> createDefaultAuthenticationProviders(HttpSecurity httpSecurity) {
		List<AuthenticationProvider> authenticationProviders = new ArrayList<>();

		OidcLogoutAuthenticationProvider oidcLogoutAuthenticationProvider = new OidcLogoutAuthenticationProvider(
				OAuth2ConfigurerUtils.getRegisteredClientRepository(httpSecurity),
				OAuth2ConfigurerUtils.getAuthorizationService(httpSecurity),
				httpSecurity.getSharedObject(SessionRegistry.class));
		authenticationProviders.add(oidcLogoutAuthenticationProvider);

		return authenticationProviders;
	}

}
