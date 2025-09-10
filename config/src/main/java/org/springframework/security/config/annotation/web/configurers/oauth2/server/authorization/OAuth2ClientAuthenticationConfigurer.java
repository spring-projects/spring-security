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
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.ClientSecretAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.JwtClientAssertionAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.PublicClientAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.X509ClientCertificateAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.web.OAuth2ClientAuthenticationFilter;
import org.springframework.security.oauth2.server.authorization.web.authentication.ClientSecretBasicAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.ClientSecretPostAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.JwtClientAssertionAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.PublicClientAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.X509ClientCertificateAuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.DelegatingAuthenticationConverter;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

/**
 * Configurer for OAuth 2.0 Client Authentication.
 *
 * @author Joe Grandja
 * @since 7.0
 * @see OAuth2AuthorizationServerConfigurer#clientAuthentication
 * @see OAuth2ClientAuthenticationFilter
 */
public final class OAuth2ClientAuthenticationConfigurer extends AbstractOAuth2Configurer {

	private RequestMatcher requestMatcher;

	private final List<AuthenticationConverter> authenticationConverters = new ArrayList<>();

	private Consumer<List<AuthenticationConverter>> authenticationConvertersConsumer = (authenticationConverters) -> {
	};

	private final List<AuthenticationProvider> authenticationProviders = new ArrayList<>();

	private Consumer<List<AuthenticationProvider>> authenticationProvidersConsumer = (authenticationProviders) -> {
	};

	private AuthenticationSuccessHandler authenticationSuccessHandler;

	private AuthenticationFailureHandler errorResponseHandler;

	/**
	 * Restrict for internal use only.
	 * @param objectPostProcessor an {@code ObjectPostProcessor}
	 */
	OAuth2ClientAuthenticationConfigurer(ObjectPostProcessor<Object> objectPostProcessor) {
		super(objectPostProcessor);
	}

	/**
	 * Adds an {@link AuthenticationConverter} used when attempting to extract client
	 * credentials from {@link HttpServletRequest} to an instance of
	 * {@link OAuth2ClientAuthenticationToken} used for authenticating the client.
	 * @param authenticationConverter an {@link AuthenticationConverter} used when
	 * attempting to extract client credentials from {@link HttpServletRequest}
	 * @return the {@link OAuth2ClientAuthenticationConfigurer} for further configuration
	 */
	public OAuth2ClientAuthenticationConfigurer authenticationConverter(
			AuthenticationConverter authenticationConverter) {
		Assert.notNull(authenticationConverter, "authenticationConverter cannot be null");
		this.authenticationConverters.add(authenticationConverter);
		return this;
	}

	/**
	 * Sets the {@code Consumer} providing access to the {@code List} of default and
	 * (optionally) added {@link #authenticationConverter(AuthenticationConverter)
	 * AuthenticationConverter}'s allowing the ability to add, remove, or customize a
	 * specific {@link AuthenticationConverter}.
	 * @param authenticationConvertersConsumer the {@code Consumer} providing access to
	 * the {@code List} of default and (optionally) added
	 * {@link AuthenticationConverter}'s
	 * @return the {@link OAuth2ClientAuthenticationConfigurer} for further configuration
	 */
	public OAuth2ClientAuthenticationConfigurer authenticationConverters(
			Consumer<List<AuthenticationConverter>> authenticationConvertersConsumer) {
		Assert.notNull(authenticationConvertersConsumer, "authenticationConvertersConsumer cannot be null");
		this.authenticationConvertersConsumer = authenticationConvertersConsumer;
		return this;
	}

	/**
	 * Adds an {@link AuthenticationProvider} used for authenticating an
	 * {@link OAuth2ClientAuthenticationToken}.
	 * @param authenticationProvider an {@link AuthenticationProvider} used for
	 * authenticating an {@link OAuth2ClientAuthenticationToken}
	 * @return the {@link OAuth2ClientAuthenticationConfigurer} for further configuration
	 */
	public OAuth2ClientAuthenticationConfigurer authenticationProvider(AuthenticationProvider authenticationProvider) {
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
	 * @return the {@link OAuth2ClientAuthenticationConfigurer} for further configuration
	 */
	public OAuth2ClientAuthenticationConfigurer authenticationProviders(
			Consumer<List<AuthenticationProvider>> authenticationProvidersConsumer) {
		Assert.notNull(authenticationProvidersConsumer, "authenticationProvidersConsumer cannot be null");
		this.authenticationProvidersConsumer = authenticationProvidersConsumer;
		return this;
	}

	/**
	 * Sets the {@link AuthenticationSuccessHandler} used for handling a successful client
	 * authentication and associating the {@link OAuth2ClientAuthenticationToken} to the
	 * {@link SecurityContext}.
	 * @param authenticationSuccessHandler the {@link AuthenticationSuccessHandler} used
	 * for handling a successful client authentication
	 * @return the {@link OAuth2ClientAuthenticationConfigurer} for further configuration
	 */
	public OAuth2ClientAuthenticationConfigurer authenticationSuccessHandler(
			AuthenticationSuccessHandler authenticationSuccessHandler) {
		this.authenticationSuccessHandler = authenticationSuccessHandler;
		return this;
	}

	/**
	 * Sets the {@link AuthenticationFailureHandler} used for handling a failed client
	 * authentication and returning the {@link OAuth2Error Error Response}.
	 * @param errorResponseHandler the {@link AuthenticationFailureHandler} used for
	 * handling a failed client authentication
	 * @return the {@link OAuth2ClientAuthenticationConfigurer} for further configuration
	 */
	public OAuth2ClientAuthenticationConfigurer errorResponseHandler(
			AuthenticationFailureHandler errorResponseHandler) {
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
		String tokenIntrospectionEndpointUri = authorizationServerSettings.isMultipleIssuersAllowed()
				? OAuth2ConfigurerUtils
					.withMultipleIssuersPattern(authorizationServerSettings.getTokenIntrospectionEndpoint())
				: authorizationServerSettings.getTokenIntrospectionEndpoint();
		String tokenRevocationEndpointUri = authorizationServerSettings.isMultipleIssuersAllowed()
				? OAuth2ConfigurerUtils
					.withMultipleIssuersPattern(authorizationServerSettings.getTokenRevocationEndpoint())
				: authorizationServerSettings.getTokenRevocationEndpoint();
		String deviceAuthorizationEndpointUri = authorizationServerSettings.isMultipleIssuersAllowed()
				? OAuth2ConfigurerUtils
					.withMultipleIssuersPattern(authorizationServerSettings.getDeviceAuthorizationEndpoint())
				: authorizationServerSettings.getDeviceAuthorizationEndpoint();
		String pushedAuthorizationRequestEndpointUri = authorizationServerSettings.isMultipleIssuersAllowed()
				? OAuth2ConfigurerUtils
					.withMultipleIssuersPattern(authorizationServerSettings.getPushedAuthorizationRequestEndpoint())
				: authorizationServerSettings.getPushedAuthorizationRequestEndpoint();
		this.requestMatcher = new OrRequestMatcher(
				PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, tokenEndpointUri),
				PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, tokenIntrospectionEndpointUri),
				PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, tokenRevocationEndpointUri),
				PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, deviceAuthorizationEndpointUri),
				PathPatternRequestMatcher.withDefaults()
					.matcher(HttpMethod.POST, pushedAuthorizationRequestEndpointUri));
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
		OAuth2ClientAuthenticationFilter clientAuthenticationFilter = new OAuth2ClientAuthenticationFilter(
				authenticationManager, this.requestMatcher);
		List<AuthenticationConverter> authenticationConverters = createDefaultAuthenticationConverters();
		if (!this.authenticationConverters.isEmpty()) {
			authenticationConverters.addAll(0, this.authenticationConverters);
		}
		this.authenticationConvertersConsumer.accept(authenticationConverters);
		clientAuthenticationFilter
			.setAuthenticationConverter(new DelegatingAuthenticationConverter(authenticationConverters));
		if (this.authenticationSuccessHandler != null) {
			clientAuthenticationFilter.setAuthenticationSuccessHandler(this.authenticationSuccessHandler);
		}
		if (this.errorResponseHandler != null) {
			clientAuthenticationFilter.setAuthenticationFailureHandler(this.errorResponseHandler);
		}
		httpSecurity.addFilterAfter(postProcess(clientAuthenticationFilter),
				AbstractPreAuthenticatedProcessingFilter.class);
	}

	@Override
	RequestMatcher getRequestMatcher() {
		return this.requestMatcher;
	}

	private static List<AuthenticationConverter> createDefaultAuthenticationConverters() {
		List<AuthenticationConverter> authenticationConverters = new ArrayList<>();

		authenticationConverters.add(new JwtClientAssertionAuthenticationConverter());
		authenticationConverters.add(new ClientSecretBasicAuthenticationConverter());
		authenticationConverters.add(new ClientSecretPostAuthenticationConverter());
		authenticationConverters.add(new PublicClientAuthenticationConverter());
		authenticationConverters.add(new X509ClientCertificateAuthenticationConverter());

		return authenticationConverters;
	}

	private static List<AuthenticationProvider> createDefaultAuthenticationProviders(HttpSecurity httpSecurity) {
		List<AuthenticationProvider> authenticationProviders = new ArrayList<>();

		RegisteredClientRepository registeredClientRepository = OAuth2ConfigurerUtils
			.getRegisteredClientRepository(httpSecurity);
		OAuth2AuthorizationService authorizationService = OAuth2ConfigurerUtils.getAuthorizationService(httpSecurity);

		JwtClientAssertionAuthenticationProvider jwtClientAssertionAuthenticationProvider = new JwtClientAssertionAuthenticationProvider(
				registeredClientRepository, authorizationService);
		authenticationProviders.add(jwtClientAssertionAuthenticationProvider);

		X509ClientCertificateAuthenticationProvider x509ClientCertificateAuthenticationProvider = new X509ClientCertificateAuthenticationProvider(
				registeredClientRepository, authorizationService);
		authenticationProviders.add(x509ClientCertificateAuthenticationProvider);

		ClientSecretAuthenticationProvider clientSecretAuthenticationProvider = new ClientSecretAuthenticationProvider(
				registeredClientRepository, authorizationService);
		PasswordEncoder passwordEncoder = OAuth2ConfigurerUtils.getOptionalBean(httpSecurity, PasswordEncoder.class);
		if (passwordEncoder != null) {
			clientSecretAuthenticationProvider.setPasswordEncoder(passwordEncoder);
		}
		authenticationProviders.add(clientSecretAuthenticationProvider);

		PublicClientAuthenticationProvider publicClientAuthenticationProvider = new PublicClientAuthenticationProvider(
				registeredClientRepository, authorizationService);
		authenticationProviders.add(publicClientAuthenticationProvider);

		return authenticationProviders;
	}

}
