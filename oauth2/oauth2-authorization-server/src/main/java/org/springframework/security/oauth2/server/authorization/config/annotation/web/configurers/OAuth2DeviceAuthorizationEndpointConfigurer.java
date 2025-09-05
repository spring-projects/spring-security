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
import org.springframework.security.oauth2.core.endpoint.OAuth2DeviceAuthorizationResponse;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2DeviceAuthorizationRequestAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2DeviceAuthorizationRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.web.OAuth2DeviceAuthorizationEndpointFilter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2DeviceAuthorizationRequestAuthenticationConverter;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.DelegatingAuthenticationConverter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * Configurer for the OAuth 2.0 Device Authorization Endpoint.
 *
 * @author Steve Riesenberg
 * @since 1.1
 * @see OAuth2AuthorizationServerConfigurer#deviceAuthorizationEndpoint
 * @see OAuth2DeviceAuthorizationEndpointFilter
 */
public final class OAuth2DeviceAuthorizationEndpointConfigurer extends AbstractOAuth2Configurer {

	private RequestMatcher requestMatcher;

	private final List<AuthenticationConverter> deviceAuthorizationRequestConverters = new ArrayList<>();

	private Consumer<List<AuthenticationConverter>> deviceAuthorizationRequestConvertersConsumer = (
			deviceAuthorizationRequestConverters) -> {
	};

	private final List<AuthenticationProvider> authenticationProviders = new ArrayList<>();

	private Consumer<List<AuthenticationProvider>> authenticationProvidersConsumer = (authenticationProviders) -> {
	};

	private AuthenticationSuccessHandler deviceAuthorizationResponseHandler;

	private AuthenticationFailureHandler errorResponseHandler;

	private String verificationUri;

	/**
	 * Restrict for internal use only.
	 * @param objectPostProcessor an {@code ObjectPostProcessor}
	 */
	OAuth2DeviceAuthorizationEndpointConfigurer(ObjectPostProcessor<Object> objectPostProcessor) {
		super(objectPostProcessor);
	}

	/**
	 * Sets the {@link AuthenticationConverter} used when attempting to extract a Device
	 * Authorization Request from {@link HttpServletRequest} to an instance of
	 * {@link OAuth2DeviceAuthorizationRequestAuthenticationToken} used for authenticating
	 * the request.
	 * @param deviceAuthorizationRequestConverter the {@link AuthenticationConverter} used
	 * when attempting to extract a Device Authorization Request from
	 * {@link HttpServletRequest}
	 * @return the {@link OAuth2DeviceAuthorizationEndpointConfigurer} for further
	 * configuration
	 */
	public OAuth2DeviceAuthorizationEndpointConfigurer deviceAuthorizationRequestConverter(
			AuthenticationConverter deviceAuthorizationRequestConverter) {
		Assert.notNull(deviceAuthorizationRequestConverter, "deviceAuthorizationRequestConverter cannot be null");
		this.deviceAuthorizationRequestConverters.add(deviceAuthorizationRequestConverter);
		return this;
	}

	/**
	 * Sets the {@code Consumer} providing access to the {@code List} of default and
	 * (optionally) added
	 * {@link #deviceAuthorizationRequestConverter(AuthenticationConverter)
	 * AuthenticationConverter}'s allowing the ability to add, remove, or customize a
	 * specific {@link AuthenticationConverter}.
	 * @param deviceAuthorizationRequestConvertersConsumer the {@code Consumer} providing
	 * access to the {@code List} of default and (optionally) added
	 * {@link AuthenticationConverter}'s
	 * @return the {@link OAuth2DeviceAuthorizationEndpointConfigurer} for further
	 * configuration
	 */
	public OAuth2DeviceAuthorizationEndpointConfigurer deviceAuthorizationRequestConverters(
			Consumer<List<AuthenticationConverter>> deviceAuthorizationRequestConvertersConsumer) {
		Assert.notNull(deviceAuthorizationRequestConvertersConsumer,
				"deviceAuthorizationRequestConvertersConsumer cannot be null");
		this.deviceAuthorizationRequestConvertersConsumer = deviceAuthorizationRequestConvertersConsumer;
		return this;
	}

	/**
	 * Adds an {@link AuthenticationProvider} used for authenticating an
	 * {@link OAuth2DeviceAuthorizationRequestAuthenticationToken}.
	 * @param authenticationProvider an {@link AuthenticationProvider} used for
	 * authenticating an {@link OAuth2DeviceAuthorizationRequestAuthenticationToken}
	 * @return the {@link OAuth2DeviceAuthorizationEndpointConfigurer} for further
	 * configuration
	 */
	public OAuth2DeviceAuthorizationEndpointConfigurer authenticationProvider(
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
	 * @return the {@link OAuth2DeviceAuthorizationEndpointConfigurer} for further
	 * configuration
	 */
	public OAuth2DeviceAuthorizationEndpointConfigurer authenticationProviders(
			Consumer<List<AuthenticationProvider>> authenticationProvidersConsumer) {
		Assert.notNull(authenticationProvidersConsumer, "authenticationProvidersConsumer cannot be null");
		this.authenticationProvidersConsumer = authenticationProvidersConsumer;
		return this;
	}

	/**
	 * Sets the {@link AuthenticationSuccessHandler} used for handling an
	 * {@link OAuth2DeviceAuthorizationRequestAuthenticationToken} and returning the
	 * {@link OAuth2DeviceAuthorizationResponse Device Authorization Response}.
	 * @param deviceAuthorizationResponseHandler the {@link AuthenticationSuccessHandler}
	 * used for handling an {@link OAuth2DeviceAuthorizationRequestAuthenticationToken}
	 * @return the {@link OAuth2DeviceAuthorizationEndpointConfigurer} for further
	 * configuration
	 */
	public OAuth2DeviceAuthorizationEndpointConfigurer deviceAuthorizationResponseHandler(
			AuthenticationSuccessHandler deviceAuthorizationResponseHandler) {
		this.deviceAuthorizationResponseHandler = deviceAuthorizationResponseHandler;
		return this;
	}

	/**
	 * Sets the {@link AuthenticationFailureHandler} used for handling an
	 * {@link OAuth2AuthenticationException} and returning the {@link OAuth2Error Error
	 * Response}.
	 * @param errorResponseHandler the {@link AuthenticationFailureHandler} used for
	 * handling an {@link OAuth2AuthenticationException}
	 * @return the {@link OAuth2DeviceAuthorizationEndpointConfigurer} for further
	 * configuration
	 */
	public OAuth2DeviceAuthorizationEndpointConfigurer errorResponseHandler(
			AuthenticationFailureHandler errorResponseHandler) {
		this.errorResponseHandler = errorResponseHandler;
		return this;
	}

	/**
	 * Sets the end-user verification {@code URI} on the authorization server.
	 * @param verificationUri the end-user verification {@code URI} on the authorization
	 * server
	 * @return the {@link OAuth2DeviceAuthorizationEndpointConfigurer} for further
	 * configuration
	 */
	public OAuth2DeviceAuthorizationEndpointConfigurer verificationUri(String verificationUri) {
		this.verificationUri = verificationUri;
		return this;
	}

	@Override
	public void init(HttpSecurity builder) {
		AuthorizationServerSettings authorizationServerSettings = OAuth2ConfigurerUtils
			.getAuthorizationServerSettings(builder);
		String deviceAuthorizationEndpointUri = authorizationServerSettings.isMultipleIssuersAllowed()
				? OAuth2ConfigurerUtils
					.withMultipleIssuersPattern(authorizationServerSettings.getDeviceAuthorizationEndpoint())
				: authorizationServerSettings.getDeviceAuthorizationEndpoint();
		this.requestMatcher = PathPatternRequestMatcher.withDefaults()
			.matcher(HttpMethod.POST, deviceAuthorizationEndpointUri);

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

		String deviceAuthorizationEndpointUri = authorizationServerSettings.isMultipleIssuersAllowed()
				? OAuth2ConfigurerUtils
					.withMultipleIssuersPattern(authorizationServerSettings.getDeviceAuthorizationEndpoint())
				: authorizationServerSettings.getDeviceAuthorizationEndpoint();
		OAuth2DeviceAuthorizationEndpointFilter deviceAuthorizationEndpointFilter = new OAuth2DeviceAuthorizationEndpointFilter(
				authenticationManager, deviceAuthorizationEndpointUri);

		List<AuthenticationConverter> authenticationConverters = createDefaultAuthenticationConverters();
		if (!this.deviceAuthorizationRequestConverters.isEmpty()) {
			authenticationConverters.addAll(0, this.deviceAuthorizationRequestConverters);
		}
		this.deviceAuthorizationRequestConvertersConsumer.accept(authenticationConverters);
		deviceAuthorizationEndpointFilter
			.setAuthenticationConverter(new DelegatingAuthenticationConverter(authenticationConverters));
		if (this.deviceAuthorizationResponseHandler != null) {
			deviceAuthorizationEndpointFilter.setAuthenticationSuccessHandler(this.deviceAuthorizationResponseHandler);
		}
		if (this.errorResponseHandler != null) {
			deviceAuthorizationEndpointFilter.setAuthenticationFailureHandler(this.errorResponseHandler);
		}
		if (StringUtils.hasText(this.verificationUri)) {
			deviceAuthorizationEndpointFilter.setVerificationUri(this.verificationUri);
		}
		builder.addFilterAfter(postProcess(deviceAuthorizationEndpointFilter), AuthorizationFilter.class);
	}

	@Override
	RequestMatcher getRequestMatcher() {
		return this.requestMatcher;
	}

	private static List<AuthenticationConverter> createDefaultAuthenticationConverters() {
		List<AuthenticationConverter> authenticationConverters = new ArrayList<>();
		authenticationConverters.add(new OAuth2DeviceAuthorizationRequestAuthenticationConverter());

		return authenticationConverters;
	}

	private static List<AuthenticationProvider> createDefaultAuthenticationProviders(HttpSecurity builder) {
		List<AuthenticationProvider> authenticationProviders = new ArrayList<>();

		OAuth2AuthorizationService authorizationService = OAuth2ConfigurerUtils.getAuthorizationService(builder);

		OAuth2DeviceAuthorizationRequestAuthenticationProvider deviceAuthorizationRequestAuthenticationProvider = new OAuth2DeviceAuthorizationRequestAuthenticationProvider(
				authorizationService);
		authenticationProviders.add(deviceAuthorizationRequestAuthenticationProvider);

		return authenticationProviders;
	}

}
