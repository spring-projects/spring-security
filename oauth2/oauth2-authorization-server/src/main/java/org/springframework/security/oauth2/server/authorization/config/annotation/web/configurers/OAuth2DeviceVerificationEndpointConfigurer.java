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
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2DeviceAuthorizationConsentAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2DeviceAuthorizationConsentAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2DeviceVerificationAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2DeviceVerificationAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.web.OAuth2DeviceVerificationEndpointFilter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2DeviceAuthorizationConsentAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2DeviceVerificationAuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.DelegatingAuthenticationConverter;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * Configurer for the OAuth 2.0 Device Verification Endpoint.
 *
 * @author Steve Riesenberg
 * @since 1.1
 * @see OAuth2AuthorizationServerConfigurer#deviceVerificationEndpoint
 * @see OAuth2DeviceVerificationEndpointFilter
 */
public final class OAuth2DeviceVerificationEndpointConfigurer extends AbstractOAuth2Configurer {

	private RequestMatcher requestMatcher;

	private final List<AuthenticationConverter> deviceVerificationRequestConverters = new ArrayList<>();

	private Consumer<List<AuthenticationConverter>> deviceVerificationRequestConvertersConsumer = (
			deviceVerificationRequestConverters) -> {
	};

	private final List<AuthenticationProvider> authenticationProviders = new ArrayList<>();

	private Consumer<List<AuthenticationProvider>> authenticationProvidersConsumer = (authenticationProviders) -> {
	};

	private AuthenticationSuccessHandler deviceVerificationResponseHandler;

	private AuthenticationFailureHandler errorResponseHandler;

	private String consentPage;

	/**
	 * Restrict for internal use only.
	 * @param objectPostProcessor an {@code ObjectPostProcessor}
	 */
	OAuth2DeviceVerificationEndpointConfigurer(ObjectPostProcessor<Object> objectPostProcessor) {
		super(objectPostProcessor);
	}

	/**
	 * Sets the {@link AuthenticationConverter} used when attempting to extract a Device
	 * Verification Request (or Device Authorization Consent) from
	 * {@link HttpServletRequest} to an instance of
	 * {@link OAuth2DeviceVerificationAuthenticationToken} or
	 * {@link OAuth2DeviceAuthorizationConsentAuthenticationToken} used for authenticating
	 * the request.
	 * @param deviceVerificationRequestConverter the {@link AuthenticationConverter} used
	 * when attempting to extract a Device Verification Request (or Device Authorization
	 * Consent) from {@link HttpServletRequest}
	 * @return the {@link OAuth2DeviceVerificationEndpointConfigurer} for further
	 * configuration
	 */
	public OAuth2DeviceVerificationEndpointConfigurer deviceVerificationRequestConverter(
			AuthenticationConverter deviceVerificationRequestConverter) {
		Assert.notNull(deviceVerificationRequestConverter, "deviceVerificationRequestConverter cannot be null");
		this.deviceVerificationRequestConverters.add(deviceVerificationRequestConverter);
		return this;
	}

	/**
	 * Sets the {@code Consumer} providing access to the {@code List} of default and
	 * (optionally) added
	 * {@link #deviceVerificationRequestConverter(AuthenticationConverter)
	 * AuthenticationConverter}'s allowing the ability to add, remove, or customize a
	 * specific {@link AuthenticationConverter}.
	 * @param deviceVerificationRequestConvertersConsumer the {@code Consumer} providing
	 * access to the {@code List} of default and (optionally) added
	 * {@link AuthenticationConverter}'s
	 * @return the {@link OAuth2DeviceVerificationEndpointConfigurer} for further
	 * configuration
	 */
	public OAuth2DeviceVerificationEndpointConfigurer deviceVerificationRequestConverters(
			Consumer<List<AuthenticationConverter>> deviceVerificationRequestConvertersConsumer) {
		Assert.notNull(deviceVerificationRequestConvertersConsumer,
				"deviceVerificationRequestConvertersConsumer cannot be null");
		this.deviceVerificationRequestConvertersConsumer = deviceVerificationRequestConvertersConsumer;
		return this;
	}

	/**
	 * Adds an {@link AuthenticationProvider} used for authenticating an
	 * {@link OAuth2DeviceVerificationAuthenticationToken} or
	 * {@link OAuth2DeviceAuthorizationConsentAuthenticationToken}.
	 * @param authenticationProvider an {@link AuthenticationProvider} used for
	 * authenticating an {@link OAuth2DeviceVerificationAuthenticationToken} or
	 * {@link OAuth2DeviceAuthorizationConsentAuthenticationToken}
	 * @return the {@link OAuth2DeviceVerificationEndpointConfigurer} for further
	 * configuration
	 */
	public OAuth2DeviceVerificationEndpointConfigurer authenticationProvider(
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
	 * @return the {@link OAuth2DeviceVerificationEndpointConfigurer} for further
	 * configuration
	 */
	public OAuth2DeviceVerificationEndpointConfigurer authenticationProviders(
			Consumer<List<AuthenticationProvider>> authenticationProvidersConsumer) {
		Assert.notNull(authenticationProvidersConsumer, "authenticationProvidersConsumer cannot be null");
		this.authenticationProvidersConsumer = authenticationProvidersConsumer;
		return this;
	}

	/**
	 * Sets the {@link AuthenticationSuccessHandler} used for handling an
	 * {@link OAuth2DeviceVerificationAuthenticationToken} and returning the response.
	 * @param deviceVerificationResponseHandler the {@link AuthenticationSuccessHandler}
	 * used for handling an {@link OAuth2DeviceVerificationAuthenticationToken}
	 * @return the {@link OAuth2DeviceVerificationEndpointConfigurer} for further
	 * configuration
	 */
	public OAuth2DeviceVerificationEndpointConfigurer deviceVerificationResponseHandler(
			AuthenticationSuccessHandler deviceVerificationResponseHandler) {
		this.deviceVerificationResponseHandler = deviceVerificationResponseHandler;
		return this;
	}

	/**
	 * Sets the {@link AuthenticationFailureHandler} used for handling an
	 * {@link OAuth2AuthenticationException} and returning the {@link OAuth2Error Error
	 * Response}.
	 * @param errorResponseHandler the {@link AuthenticationFailureHandler} used for
	 * handling an {@link OAuth2AuthenticationException}
	 * @return the {@link OAuth2DeviceVerificationEndpointConfigurer} for further
	 * configuration
	 */
	public OAuth2DeviceVerificationEndpointConfigurer errorResponseHandler(
			AuthenticationFailureHandler errorResponseHandler) {
		this.errorResponseHandler = errorResponseHandler;
		return this;
	}

	/**
	 * Specify the URI to redirect Resource Owners to if consent is required during the
	 * {@code device_code} flow. A default consent page will be generated when this
	 * attribute is not specified.
	 *
	 * If a URI is specified, applications are required to process the specified URI to
	 * generate a consent page. The query string will contain the following parameters:
	 *
	 * <ul>
	 * <li>{@code client_id} - the client identifier</li>
	 * <li>{@code scope} - a space-delimited list of scopes present in the device
	 * authorization request</li>
	 * <li>{@code state} - a CSRF protection token</li>
	 * <li>{@code user_code} - the user code</li>
	 * </ul>
	 *
	 * In general, the consent page should create a form that submits a request with the
	 * following requirements:
	 *
	 * <ul>
	 * <li>It must be an HTTP POST</li>
	 * <li>It must be submitted to
	 * {@link AuthorizationServerSettings#getDeviceVerificationEndpoint()}</li>
	 * <li>It must include the received {@code client_id} as an HTTP parameter</li>
	 * <li>It must include the received {@code state} as an HTTP parameter</li>
	 * <li>It must include the list of {@code scope}s the {@code Resource Owner} consented
	 * to as an HTTP parameter</li>
	 * <li>It must include the received {@code user_code} as an HTTP parameter</li>
	 * </ul>
	 * @param consentPage the URI of the custom consent page to redirect to if consent is
	 * required (e.g. "/oauth2/consent")
	 * @return the {@link OAuth2DeviceVerificationEndpointConfigurer} for further
	 * configuration
	 */
	public OAuth2DeviceVerificationEndpointConfigurer consentPage(String consentPage) {
		this.consentPage = consentPage;
		return this;
	}

	@Override
	public void init(HttpSecurity builder) {
		AuthorizationServerSettings authorizationServerSettings = OAuth2ConfigurerUtils
			.getAuthorizationServerSettings(builder);
		String deviceVerificationEndpointUri = authorizationServerSettings.isMultipleIssuersAllowed()
				? OAuth2ConfigurerUtils
					.withMultipleIssuersPattern(authorizationServerSettings.getDeviceVerificationEndpoint())
				: authorizationServerSettings.getDeviceVerificationEndpoint();
		this.requestMatcher = new OrRequestMatcher(
				PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.GET, deviceVerificationEndpointUri),
				PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, deviceVerificationEndpointUri));

		List<AuthenticationProvider> authenticationProviders = createDefaultAuthenticationProviders(builder);
		if (!this.authenticationProviders.isEmpty()) {
			authenticationProviders.addAll(0, this.authenticationProviders);
		}
		this.authenticationProvidersConsumer.accept(authenticationProviders);
		authenticationProviders
			.forEach((authenticationProvider) -> builder.authenticationProvider(postProcess(authenticationProvider)));
	}

	@Override
	public void configure(HttpSecurity builder) {
		AuthenticationManager authenticationManager = builder.getSharedObject(AuthenticationManager.class);
		AuthorizationServerSettings authorizationServerSettings = OAuth2ConfigurerUtils
			.getAuthorizationServerSettings(builder);

		String deviceVerificationEndpointUri = authorizationServerSettings.isMultipleIssuersAllowed()
				? OAuth2ConfigurerUtils
					.withMultipleIssuersPattern(authorizationServerSettings.getDeviceVerificationEndpoint())
				: authorizationServerSettings.getDeviceVerificationEndpoint();
		OAuth2DeviceVerificationEndpointFilter deviceVerificationEndpointFilter = new OAuth2DeviceVerificationEndpointFilter(
				authenticationManager, deviceVerificationEndpointUri);
		List<AuthenticationConverter> authenticationConverters = createDefaultAuthenticationConverters();
		if (!this.deviceVerificationRequestConverters.isEmpty()) {
			authenticationConverters.addAll(0, this.deviceVerificationRequestConverters);
		}
		this.deviceVerificationRequestConvertersConsumer.accept(authenticationConverters);
		deviceVerificationEndpointFilter
			.setAuthenticationConverter(new DelegatingAuthenticationConverter(authenticationConverters));
		if (this.deviceVerificationResponseHandler != null) {
			deviceVerificationEndpointFilter.setAuthenticationSuccessHandler(this.deviceVerificationResponseHandler);
		}
		if (this.errorResponseHandler != null) {
			deviceVerificationEndpointFilter.setAuthenticationFailureHandler(this.errorResponseHandler);
		}
		if (StringUtils.hasText(this.consentPage)) {
			deviceVerificationEndpointFilter.setConsentPage(this.consentPage);
		}
		builder.addFilterBefore(postProcess(deviceVerificationEndpointFilter),
				AbstractPreAuthenticatedProcessingFilter.class);
	}

	@Override
	RequestMatcher getRequestMatcher() {
		return this.requestMatcher;
	}

	private static List<AuthenticationConverter> createDefaultAuthenticationConverters() {
		List<AuthenticationConverter> authenticationConverters = new ArrayList<>();

		authenticationConverters.add(new OAuth2DeviceVerificationAuthenticationConverter());
		authenticationConverters.add(new OAuth2DeviceAuthorizationConsentAuthenticationConverter());

		return authenticationConverters;
	}

	private static List<AuthenticationProvider> createDefaultAuthenticationProviders(HttpSecurity builder) {
		RegisteredClientRepository registeredClientRepository = OAuth2ConfigurerUtils
			.getRegisteredClientRepository(builder);
		OAuth2AuthorizationService authorizationService = OAuth2ConfigurerUtils.getAuthorizationService(builder);
		OAuth2AuthorizationConsentService authorizationConsentService = OAuth2ConfigurerUtils
			.getAuthorizationConsentService(builder);

		List<AuthenticationProvider> authenticationProviders = new ArrayList<>();

		// @formatter:off
		OAuth2DeviceVerificationAuthenticationProvider deviceVerificationAuthenticationProvider =
				new OAuth2DeviceVerificationAuthenticationProvider(
						registeredClientRepository, authorizationService, authorizationConsentService);
		// @formatter:on
		authenticationProviders.add(deviceVerificationAuthenticationProvider);

		// @formatter:off
		OAuth2DeviceAuthorizationConsentAuthenticationProvider deviceAuthorizationConsentAuthenticationProvider =
				new OAuth2DeviceAuthorizationConsentAuthenticationProvider(
						registeredClientRepository, authorizationService, authorizationConsentService);
		// @formatter:on
		authenticationProviders.add(deviceAuthorizationConsentAuthenticationProvider);

		return authenticationProviders;
	}

}
