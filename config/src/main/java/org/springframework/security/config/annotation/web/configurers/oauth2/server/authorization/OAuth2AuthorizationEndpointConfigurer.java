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

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

import jakarta.servlet.Filter;
import jakarta.servlet.http.HttpServletRequest;

import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationValidator;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationConsentAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationConsentAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.web.OAuth2AuthorizationEndpointFilter;
import org.springframework.security.oauth2.server.authorization.web.OidcPromptNoneExceptionHandlingFilter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeRequestAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeRequestAuthenticationFailureHandler;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationConsentAuthenticationConverter;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.DelegatingAuthenticationConverter;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.ReflectionUtils;
import org.springframework.util.StringUtils;

/**
 * Configurer for the OAuth 2.0 Authorization Endpoint.
 *
 * @author Joe Grandja
 * @since 7.0
 * @see OAuth2AuthorizationServerConfigurer#authorizationEndpoint
 * @see OAuth2AuthorizationEndpointFilter
 */
public final class OAuth2AuthorizationEndpointConfigurer extends AbstractOAuth2Configurer {

	private RequestMatcher requestMatcher;

	private final List<AuthenticationConverter> authorizationRequestConverters = new ArrayList<>();

	private Consumer<List<AuthenticationConverter>> authorizationRequestConvertersConsumer = (
			authorizationRequestConverters) -> {
	};

	private final List<AuthenticationProvider> authenticationProviders = new ArrayList<>();

	private Consumer<List<AuthenticationProvider>> authenticationProvidersConsumer = (authenticationProviders) -> {
	};

	private AuthenticationSuccessHandler authorizationResponseHandler;

	private AuthenticationFailureHandler errorResponseHandler;

	private String consentPage;

	private Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> authorizationCodeRequestAuthenticationValidator;

	private Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> authorizationCodeRequestAuthenticationValidatorComposite;

	private SessionAuthenticationStrategy sessionAuthenticationStrategy;

	/**
	 * Restrict for internal use only.
	 * @param objectPostProcessor an {@code ObjectPostProcessor}
	 */
	OAuth2AuthorizationEndpointConfigurer(ObjectPostProcessor<Object> objectPostProcessor) {
		super(objectPostProcessor);
	}

	/**
	 * Adds an {@link AuthenticationConverter} used when attempting to extract an
	 * Authorization Request (or Consent) from {@link HttpServletRequest} to an instance
	 * of {@link OAuth2AuthorizationCodeRequestAuthenticationToken} or
	 * {@link OAuth2AuthorizationConsentAuthenticationToken} used for authenticating the
	 * request.
	 * @param authorizationRequestConverter an {@link AuthenticationConverter} used when
	 * attempting to extract an Authorization Request (or Consent) from
	 * {@link HttpServletRequest}
	 * @return the {@link OAuth2AuthorizationEndpointConfigurer} for further configuration
	 */
	public OAuth2AuthorizationEndpointConfigurer authorizationRequestConverter(
			AuthenticationConverter authorizationRequestConverter) {
		Assert.notNull(authorizationRequestConverter, "authorizationRequestConverter cannot be null");
		this.authorizationRequestConverters.add(authorizationRequestConverter);
		return this;
	}

	/**
	 * Sets the {@code Consumer} providing access to the {@code List} of default and
	 * (optionally) added {@link #authorizationRequestConverter(AuthenticationConverter)
	 * AuthenticationConverter}'s allowing the ability to add, remove, or customize a
	 * specific {@link AuthenticationConverter}.
	 * @param authorizationRequestConvertersConsumer the {@code Consumer} providing access
	 * to the {@code List} of default and (optionally) added
	 * {@link AuthenticationConverter}'s
	 * @return the {@link OAuth2AuthorizationEndpointConfigurer} for further configuration
	 */
	public OAuth2AuthorizationEndpointConfigurer authorizationRequestConverters(
			Consumer<List<AuthenticationConverter>> authorizationRequestConvertersConsumer) {
		Assert.notNull(authorizationRequestConvertersConsumer, "authorizationRequestConvertersConsumer cannot be null");
		this.authorizationRequestConvertersConsumer = authorizationRequestConvertersConsumer;
		return this;
	}

	/**
	 * Adds an {@link AuthenticationProvider} used for authenticating an
	 * {@link OAuth2AuthorizationCodeRequestAuthenticationToken}.
	 * @param authenticationProvider an {@link AuthenticationProvider} used for
	 * authenticating an {@link OAuth2AuthorizationCodeRequestAuthenticationToken}
	 * @return the {@link OAuth2AuthorizationEndpointConfigurer} for further configuration
	 */
	public OAuth2AuthorizationEndpointConfigurer authenticationProvider(AuthenticationProvider authenticationProvider) {
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
	 * @return the {@link OAuth2AuthorizationEndpointConfigurer} for further configuration
	 */
	public OAuth2AuthorizationEndpointConfigurer authenticationProviders(
			Consumer<List<AuthenticationProvider>> authenticationProvidersConsumer) {
		Assert.notNull(authenticationProvidersConsumer, "authenticationProvidersConsumer cannot be null");
		this.authenticationProvidersConsumer = authenticationProvidersConsumer;
		return this;
	}

	/**
	 * Sets the {@link AuthenticationSuccessHandler} used for handling an
	 * {@link OAuth2AuthorizationCodeRequestAuthenticationToken} and returning the
	 * {@link OAuth2AuthorizationResponse Authorization Response}.
	 * @param authorizationResponseHandler the {@link AuthenticationSuccessHandler} used
	 * for handling an {@link OAuth2AuthorizationCodeRequestAuthenticationToken}
	 * @return the {@link OAuth2AuthorizationEndpointConfigurer} for further configuration
	 */
	public OAuth2AuthorizationEndpointConfigurer authorizationResponseHandler(
			AuthenticationSuccessHandler authorizationResponseHandler) {
		this.authorizationResponseHandler = authorizationResponseHandler;
		return this;
	}

	/**
	 * Sets the {@link AuthenticationFailureHandler} used for handling an
	 * {@link OAuth2AuthorizationCodeRequestAuthenticationException} and returning the
	 * {@link OAuth2Error Error Response}.
	 * @param errorResponseHandler the {@link AuthenticationFailureHandler} used for
	 * handling an {@link OAuth2AuthorizationCodeRequestAuthenticationException}
	 * @return the {@link OAuth2AuthorizationEndpointConfigurer} for further configuration
	 */
	public OAuth2AuthorizationEndpointConfigurer errorResponseHandler(
			AuthenticationFailureHandler errorResponseHandler) {
		this.errorResponseHandler = errorResponseHandler;
		return this;
	}

	/**
	 * Specify the URI to redirect Resource Owners to if consent is required during the
	 * {@code authorization_code} flow. A default consent page will be generated when this
	 * attribute is not specified.
	 *
	 * If a URI is specified, applications are required to process the specified URI to
	 * generate a consent page. The query string will contain the following parameters:
	 *
	 * <ul>
	 * <li>{@code client_id} - the client identifier</li>
	 * <li>{@code scope} - a space-delimited list of scopes present in the authorization
	 * request</li>
	 * <li>{@code state} - a CSRF protection token</li>
	 * </ul>
	 *
	 * In general, the consent page should create a form that submits a request with the
	 * following requirements:
	 *
	 * <ul>
	 * <li>It must be an HTTP POST</li>
	 * <li>It must be submitted to
	 * {@link AuthorizationServerSettings#getAuthorizationEndpoint()}</li>
	 * <li>It must include the received {@code client_id} as an HTTP parameter</li>
	 * <li>It must include the received {@code state} as an HTTP parameter</li>
	 * <li>It must include the list of {@code scope}s the {@code Resource Owner} consented
	 * to as an HTTP parameter</li>
	 * </ul>
	 * @param consentPage the URI of the custom consent page to redirect to if consent is
	 * required (e.g. "/oauth2/consent")
	 * @return the {@link OAuth2AuthorizationEndpointConfigurer} for further configuration
	 */
	public OAuth2AuthorizationEndpointConfigurer consentPage(String consentPage) {
		this.consentPage = consentPage;
		return this;
	}

	void addAuthorizationCodeRequestAuthenticationValidator(
			Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> authenticationValidator) {
		this.authorizationCodeRequestAuthenticationValidator = (this.authorizationCodeRequestAuthenticationValidator == null)
				? authenticationValidator
				: this.authorizationCodeRequestAuthenticationValidator.andThen(authenticationValidator);
	}

	void setSessionAuthenticationStrategy(SessionAuthenticationStrategy sessionAuthenticationStrategy) {
		this.sessionAuthenticationStrategy = sessionAuthenticationStrategy;
	}

	@Override
	void init(HttpSecurity httpSecurity) {
		AuthorizationServerSettings authorizationServerSettings = OAuth2ConfigurerUtils
			.getAuthorizationServerSettings(httpSecurity);
		String authorizationEndpointUri = authorizationServerSettings.isMultipleIssuersAllowed()
				? OAuth2ConfigurerUtils
					.withMultipleIssuersPattern(authorizationServerSettings.getAuthorizationEndpoint())
				: authorizationServerSettings.getAuthorizationEndpoint();
		this.requestMatcher = new OrRequestMatcher(
				PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.GET, authorizationEndpointUri),
				PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, authorizationEndpointUri));
		List<AuthenticationProvider> authenticationProviders = createDefaultAuthenticationProviders(httpSecurity);
		if (!this.authenticationProviders.isEmpty()) {
			authenticationProviders.addAll(0, this.authenticationProviders);
		}
		this.authenticationProvidersConsumer.accept(authenticationProviders);
		authenticationProviders.forEach((authenticationProvider) -> {
			httpSecurity.authenticationProvider(postProcess(authenticationProvider));
			if (authenticationProvider instanceof OAuth2AuthorizationCodeRequestAuthenticationProvider) {
				Method method = ReflectionUtils.findMethod(OAuth2AuthorizationCodeRequestAuthenticationProvider.class,
						"getAuthenticationValidatorComposite");
				ReflectionUtils.makeAccessible(method);
				this.authorizationCodeRequestAuthenticationValidatorComposite = (Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext>) ReflectionUtils
					.invokeMethod(method, authenticationProvider);
			}
		});
	}

	@Override
	void configure(HttpSecurity httpSecurity) {
		AuthenticationManager authenticationManager = httpSecurity.getSharedObject(AuthenticationManager.class);
		AuthorizationServerSettings authorizationServerSettings = OAuth2ConfigurerUtils
			.getAuthorizationServerSettings(httpSecurity);
		String authorizationEndpointUri = authorizationServerSettings.isMultipleIssuersAllowed()
				? OAuth2ConfigurerUtils
					.withMultipleIssuersPattern(authorizationServerSettings.getAuthorizationEndpoint())
				: authorizationServerSettings.getAuthorizationEndpoint();
		OAuth2AuthorizationEndpointFilter authorizationEndpointFilter = new OAuth2AuthorizationEndpointFilter(
				authenticationManager, authorizationEndpointUri);
		List<AuthenticationConverter> authenticationConverters = createDefaultAuthenticationConverters();
		if (!this.authorizationRequestConverters.isEmpty()) {
			authenticationConverters.addAll(0, this.authorizationRequestConverters);
		}
		this.authorizationRequestConvertersConsumer.accept(authenticationConverters);
		authorizationEndpointFilter
			.setAuthenticationConverter(new DelegatingAuthenticationConverter(authenticationConverters));
		if (this.authorizationResponseHandler != null) {
			authorizationEndpointFilter.setAuthenticationSuccessHandler(this.authorizationResponseHandler);
		}
		if (this.errorResponseHandler != null) {
			authorizationEndpointFilter.setAuthenticationFailureHandler(this.errorResponseHandler);
		}
		if (StringUtils.hasText(this.consentPage)) {
			authorizationEndpointFilter.setConsentPage(this.consentPage);
		}
		if (this.sessionAuthenticationStrategy != null) {
			authorizationEndpointFilter.setSessionAuthenticationStrategy(this.sessionAuthenticationStrategy);
		}

		// Create and add OidcPromptNoneExceptionHandlingFilter
		AuthenticationFailureHandler failureHandler = (this.errorResponseHandler != null) ? this.errorResponseHandler
				: new OAuth2AuthorizationCodeRequestAuthenticationFailureHandler();

		OidcPromptNoneExceptionHandlingFilter promptNoneFilter = new OidcPromptNoneExceptionHandlingFilter(
				this.requestMatcher, new DelegatingAuthenticationConverter(authenticationConverters), failureHandler);

		httpSecurity.addFilterBefore(postProcess(promptNoneFilter), AuthorizationFilter.class);

		httpSecurity.addFilterAfter(postProcess(authorizationEndpointFilter), AuthorizationFilter.class);
		// Create and add
		// OAuth2AuthorizationEndpointFilter.OAuth2AuthorizationCodeRequestValidatingFilter
		Method method = ReflectionUtils.findMethod(OAuth2AuthorizationEndpointFilter.class,
				"createAuthorizationCodeRequestValidatingFilter", RegisteredClientRepository.class, Consumer.class);
		ReflectionUtils.makeAccessible(method);
		RegisteredClientRepository registeredClientRepository = OAuth2ConfigurerUtils
			.getRegisteredClientRepository(httpSecurity);
		Filter authorizationCodeRequestValidatingFilter = (Filter) ReflectionUtils.invokeMethod(method,
				authorizationEndpointFilter, registeredClientRepository,
				this.authorizationCodeRequestAuthenticationValidatorComposite);
		httpSecurity.addFilterBefore(postProcess(authorizationCodeRequestValidatingFilter),
				AbstractPreAuthenticatedProcessingFilter.class);
	}

	@Override
	RequestMatcher getRequestMatcher() {
		return this.requestMatcher;
	}

	private static List<AuthenticationConverter> createDefaultAuthenticationConverters() {
		List<AuthenticationConverter> authenticationConverters = new ArrayList<>();

		authenticationConverters.add(new OAuth2AuthorizationCodeRequestAuthenticationConverter());
		authenticationConverters.add(new OAuth2AuthorizationConsentAuthenticationConverter());

		return authenticationConverters;
	}

	private List<AuthenticationProvider> createDefaultAuthenticationProviders(HttpSecurity httpSecurity) {
		List<AuthenticationProvider> authenticationProviders = new ArrayList<>();

		OAuth2AuthorizationCodeRequestAuthenticationProvider authorizationCodeRequestAuthenticationProvider = new OAuth2AuthorizationCodeRequestAuthenticationProvider(
				OAuth2ConfigurerUtils.getRegisteredClientRepository(httpSecurity),
				OAuth2ConfigurerUtils.getAuthorizationService(httpSecurity),
				OAuth2ConfigurerUtils.getAuthorizationConsentService(httpSecurity));
		if (this.authorizationCodeRequestAuthenticationValidator != null) {
			authorizationCodeRequestAuthenticationProvider
				.setAuthenticationValidator(new OAuth2AuthorizationCodeRequestAuthenticationValidator()
					.andThen(this.authorizationCodeRequestAuthenticationValidator));
		}
		authenticationProviders.add(authorizationCodeRequestAuthenticationProvider);

		OAuth2AuthorizationConsentAuthenticationProvider authorizationConsentAuthenticationProvider = new OAuth2AuthorizationConsentAuthenticationProvider(
				OAuth2ConfigurerUtils.getRegisteredClientRepository(httpSecurity),
				OAuth2ConfigurerUtils.getAuthorizationService(httpSecurity),
				OAuth2ConfigurerUtils.getAuthorizationConsentService(httpSecurity));
		authenticationProviders.add(authorizationConsentAuthenticationProvider);

		return authenticationProviders;
	}

}
